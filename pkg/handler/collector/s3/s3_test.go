//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package s3

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/s3/bucket"
	"github.com/guacsec/guac/pkg/handler/collector/s3/messaging"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func TestSqsMessageGetItem(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		want    string
		wantErr bool
	}{
		{
			name: "plain key",
			key:  "camera/build/sbom.json",
			want: "camera/build/sbom.json",
		},
		{
			name: "access controller path with spaces",
			key:  "Access+Controllers/Clooney/build/sbom.json",
			want: "Access Controllers/Clooney/build/sbom.json",
		},
		{
			name: "command connector path with multiple spaces",
			key:  "Command+Connector/BOX+OS/build/sbom.json",
			want: "Command Connector/BOX OS/build/sbom.json",
		},
		{
			name: "percent encoded characters",
			key:  "Access%20Controllers%2FClooney%2Fsbom%23%25.json",
			want: "Access Controllers/Clooney/sbom#%.json",
		},
		{
			name: "literal plus and space",
			key:  "camera%2Bcv/build+name/sbom.json",
			want: "camera+cv/build name/sbom.json",
		},
		{
			name: "decode only once",
			key:  "camera/build%2520name/sbom%252B.json",
			want: "camera/build%20name/sbom%2B.json",
		},
		{
			name: "unicode",
			key:  "camera/%E6%B5%8B%E8%AF%95/sbom.json",
			want: "camera/测试/sbom.json",
		},
		{
			name:    "invalid percent escape",
			key:     "camera/sbom%ZZ.json",
			wantErr: true,
		},
		{
			name:    "incomplete percent escape",
			key:     "camera/sbom%2",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &messaging.SqsMessage{
				Records: []messaging.SqsRecord{
					{S3: messaging.SqsS3{Object: messaging.SqsObject{Key: tt.key}}},
				},
			}
			for i := 0; i < 2; i++ {
				got, err := msg.GetItem()
				if tt.wantErr {
					var escapeErr url.EscapeError
					if !errors.As(err, &escapeErr) {
						t.Fatalf("GetItem() error = %v, want URL escape error", err)
					}
				} else if err != nil {
					t.Fatalf("GetItem() error = %v", err)
				}
				if got != tt.want {
					t.Errorf("GetItem() = %q, want %q", got, tt.want)
				}
				if msg.Records[0].S3.Object.Key != tt.key {
					t.Fatal("GetItem() mutated the notification key")
				}
			}
		})
	}
	t.Run("missing records", func(t *testing.T) {
		got, err := (&messaging.SqsMessage{}).GetItem()
		if err == nil || got != "" {
			t.Fatalf("GetItem() = %q, %v, want empty key and error", got, err)
		}
	})
}

// Test message
type TestMessage struct {
	item   string
	bucket string
	event  messaging.EventName
}

func (msg *TestMessage) GetEvent() (messaging.EventName, error) {
	return msg.event, nil
}

func (msg *TestMessage) GetBucket() (string, error) {
	return msg.bucket, nil
}

func (msg *TestMessage) GetItem() (string, error) {
	return msg.item, nil
}

// Test Message Provider
type TestProvider struct {
	queue string
}

func NewTestProvider(queue string) TestProvider {
	return TestProvider{queue}
}

func (t *TestProvider) ReceiveMessage(context.Context) (messaging.Message, error) {
	time.Sleep(2 * time.Second)

	return &TestMessage{
		item:   "test-message",
		bucket: t.queue,
		event:  messaging.PUT,
	}, nil
}

func (t *TestProvider) Close(ctx context.Context) error {
	return nil
}

// Test Message Provider builder
type TestMpBuilder struct {
}

func (tb *TestMpBuilder) GetMessageProvider(config messaging.MessageProviderConfig) (messaging.MessageProvider, error) {
	provider := NewTestProvider(config.Queue)
	return &provider, nil
}

// Test Bucket
type TestBucket struct {
}

func (td *TestBucket) ListFiles(ctx context.Context, bucket string, prefix string, token *string, max int32) ([]string, *string, error) {
	return []string{"no-poll-item"}, nil, nil
}

func (td *TestBucket) DownloadFile(ctx context.Context, bucket string, item string) ([]byte, error) {
	return []byte("{\"key\": \"value\"}"), nil
}

func (td *TestBucket) GetEncoding(ctx context.Context, bucket string, item string) (string, error) {
	return "application/json", nil
}

type TestBucketBuilder struct {
}

func (td *TestBucketBuilder) GetDownloader(url string, region string) bucket.Bucket {
	return &TestBucket{}
}

func TestS3Collector(t *testing.T) {
	ctx := context.Background()

	t.Run("no polling", func(t *testing.T) { testNoPolling(t, ctx) })
	t.Run("queues split polling", func(t *testing.T) { testQueuesSplitPolling(t, ctx) })
}

func testQueuesSplitPolling(t *testing.T, ctx context.Context) {
	s3Collector := NewS3Collector(S3CollectorConfig{
		Queues:        "q1,q2",
		MpBuilder:     &TestMpBuilder{},
		BucketBuilder: &TestBucketBuilder{},
		Poll:          true,
	})

	collector.DeregisterDocumentCollector(S3CollectorType)
	if err := collector.RegisterDocumentCollector(s3Collector, S3CollectorType); err != nil &&
		!errors.Is(err, collector.ErrCollectorOverwrite) {
		t.Fatalf("could not register collector: %v", err)
	}

	// create fake emitter and handler
	var s []*processor.Document
	em := func(d *processor.Document) error {
		s = append(s, d)
		return nil
	}
	eh := func(err error) bool {
		return true
	}

	// spawn collector
	var wg sync.WaitGroup
	wg.Add(1)

	cancelCtx, cancel := context.WithCancel(ctx)
	go func() {
		err := collector.Collect(cancelCtx, em, eh)
		if err != nil {
			t.Errorf("error collecting: %v", err)
		}
		wg.Done()
	}()

	// wait for a while to get some messages
	time.Sleep(5 * time.Second)

	// shut down collector
	cancel()

	wg.Wait()

	if len(s) == 0 {
		t.Errorf("no documents returned")
	}

	for _, doc := range s {
		if doc.Blob != nil && !bytes.Equal(doc.Blob, []byte("{\"key\": \"value\"}")) {
			t.Errorf("wrong item returned")
		}

		if doc.Encoding != "UNKNOWN" {
			t.Errorf("wrong encoding returned: %s", doc.Encoding)
		}

		assertSource(t, "test-message", doc)
	}
}

func testNoPolling(t *testing.T, ctx context.Context) {
	s3Collector := NewS3Collector(S3CollectorConfig{
		BucketBuilder: &TestBucketBuilder{},
		S3Bucket:      "no-poll-bucket",
		S3Item:        "no-poll-item",
		Poll:          false,
	})

	collector.DeregisterDocumentCollector(S3CollectorType)
	if err := collector.RegisterDocumentCollector(s3Collector, S3CollectorType); err != nil &&
		!errors.Is(err, collector.ErrCollectorOverwrite) {
		t.Fatalf("could not register collector: %v", err)
	}

	// create fake emitter and handler
	var s []*processor.Document
	em := func(d *processor.Document) error {
		s = append(s, d)
		return nil
	}
	eh := func(err error) bool {
		return true
	}

	err := collector.Collect(ctx, em, eh)
	if err != nil {
		t.Errorf("error collecting: %v", err)
	}

	if len(s) == 0 {
		t.Errorf("no documents returned")
	}

	if s[0].Blob != nil && !bytes.Equal(s[0].Blob, []byte("{\"key\": \"value\"}")) {
		t.Errorf("wrong item returned")
	}

	assertSource(t, "no-poll-item", s[0])
}

func assertSource(t *testing.T, wantSource string, doc *processor.Document) {
	wantDocRef := events.GetDocRef(doc.Blob)
	if doc.SourceInformation.DocumentRef != wantDocRef {
		t.Errorf("want DocumentRef = %s, got = %s", wantDocRef, doc.SourceInformation.DocumentRef)
	}

	if doc.SourceInformation.Source != wantSource {
		t.Errorf("want Source = %s, got = %s", wantSource, doc.SourceInformation.Source)
	}

	const wantCollector string = "S3CollectorType"
	if doc.SourceInformation.Collector != wantCollector {
		t.Errorf("want Collector = %s, got = %s", wantCollector, doc.SourceInformation.Collector)
	}
}
