/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dynamiccertificates

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

// DynamicCertKeyPairContent provides a CertKeyContentProvider that can dynamically react to new file content
type DynamicCertKeyPairContent struct {
	name string

	// certFile is the name of the certificate file to read.
	certFile string
	// keyFile is the name of the key file to read.
	keyFile string

	// servingCert is a certKeyContent that contains the last read, non-zero length content of the key and cert
	certKeyPair atomic.Value

	listeners []Listener

	// queue only ever has one item, but it has nice error handling backoff/retry semantics
	queue workqueue.RateLimitingInterface
}

var _ Notifier = &DynamicCertKeyPairContent{}
var _ CertKeyContentProvider = &DynamicCertKeyPairContent{}
var _ ControllerRunner = &DynamicCertKeyPairContent{}

// NewDynamicServingContentFromFiles returns a dynamic CertKeyContentProvider based on a cert and key filename
func NewDynamicServingContentFromFiles(purpose, certFile, keyFile string) (*DynamicCertKeyPairContent, error) {
	if len(certFile) == 0 || len(keyFile) == 0 {
		return nil, fmt.Errorf("missing filename for serving cert")
	}
	name := fmt.Sprintf("%s::%s::%s", purpose, certFile, keyFile)

	ret := &DynamicCertKeyPairContent{
		name:     name,
		certFile: certFile,
		keyFile:  keyFile,
		queue:    workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), fmt.Sprintf("DynamicCABundle-%s", purpose)),
	}
	if err := ret.loadCertKeyPair(); err != nil {
		return nil, err
	}

	return ret, nil
}

// AddListener adds a listener to be notified when the serving cert content changes.
func (c *DynamicCertKeyPairContent) AddListener(listener Listener) {
	c.listeners = append(c.listeners, listener)
}

// loadServingCert determines the next set of content for the file.
func (c *DynamicCertKeyPairContent) loadCertKeyPair() error {
	cert, err := ioutil.ReadFile(c.certFile)
	if err != nil {
		return err
	}
	key, err := ioutil.ReadFile(c.keyFile)
	if err != nil {
		return err
	}
	if len(cert) == 0 || len(key) == 0 {
		return fmt.Errorf("missing content for serving cert %q", c.Name())
	}

	// Ensure that the key matches the cert and both are valid
	_, err = tls.X509KeyPair(cert, key)
	if err != nil {
		return err
	}

	newCertKey := &certKeyContent{
		cert: cert,
		key:  key,
	}

	// check to see if we have a change. If the values are the same, do nothing.
	existing, ok := c.certKeyPair.Load().(*certKeyContent)
	if ok && existing != nil && existing.Equal(newCertKey) {
		return nil
	}

	c.certKeyPair.Store(newCertKey)
	klog.V(2).Infof("Loaded a new cert/key pair for %q", c.Name())

	for _, listener := range c.listeners {
		listener.Enqueue()
	}

	return nil
}

// RunOnce runs a single sync loop
func (c *DynamicCertKeyPairContent) RunOnce() error {
	return c.loadCertKeyPair()
}

// Run starts the controller and blocks until stopCh is closed.
func (c *DynamicCertKeyPairContent) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting %s", c.name)
	defer klog.Infof("Shutting down %s", c.name)

	// doesn't matter what workers say, only start one.
	go wait.Until(c.runWorker, time.Second, stopCh)

	// start the loop that watches the cert and key files until stopCh is closed.
	go wait.Until(func() {
		if err := c.watchCertKeyFile(stopCh); err != nil {
			klog.ErrorS(err, "Failed to watch cert and key file, will retry later")
		}
	}, time.Minute, stopCh)

	<-stopCh
}

func (c *DynamicCertKeyPairContent) watchCertKeyFile(stopCh <-chan struct{}) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("error creating fsnotify watcher: %v", err)
	}
	defer w.Close()

	if err = w.Add(c.certFile); err != nil {
		return fmt.Errorf("error adding watch for file %s: %v", c.certFile, err)
	}
	if err = w.Add(c.keyFile); err != nil {
		return fmt.Errorf("error adding watch for file %s: %v", c.keyFile, err)
	}
	// Reload the content when it starts a new watch as the file may have changed.
	c.queue.Add(workItemKey)

	for {
		select {
		case e := <-w.Events:
			c.queue.Add(workItemKey)
			// The original watched file is removed or renamed, restarting a new watch.
			if e.Op&(fsnotify.Remove|e.Op&fsnotify.Rename) > 0 {
				if err := w.Remove(e.Name); err != nil {
					klog.InfoS("Failed to remove file watch, it may have been deleted", "file", e.Name, "err", err)
				}
				if err := w.Add(e.Name); err != nil {
					return fmt.Errorf("error adding watch for file %s: %v", e.Name, err)
				}
				c.queue.Add(workItemKey)
			}
		case err := <-w.Errors:
			return fmt.Errorf("received fsnotify error: %v", err)
		case <-stopCh:
			return nil
		}
	}
}

func (c *DynamicCertKeyPairContent) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *DynamicCertKeyPairContent) processNextWorkItem() bool {
	dsKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(dsKey)

	err := c.loadCertKeyPair()
	if err == nil {
		c.queue.Forget(dsKey)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with : %v", dsKey, err))
	c.queue.AddRateLimited(dsKey)

	return true
}

// Name is just an identifier
func (c *DynamicCertKeyPairContent) Name() string {
	return c.name
}

// CurrentCertKeyContent provides cert and key byte content
func (c *DynamicCertKeyPairContent) CurrentCertKeyContent() ([]byte, []byte) {
	certKeyContent := c.certKeyPair.Load().(*certKeyContent)
	return certKeyContent.cert, certKeyContent.key
}
