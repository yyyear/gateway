package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/yyyear/RouterModel"
	"github.com/yyyear/YY"

	"github.com/nats-io/nats.go"
	nc "github.com/yyyear/natsClient"
)

func init() {
	YY.Debug("NATS Service Init")
}

var natsClient *nc.NATS

var (
	natsMu           sync.RWMutex
	heartbeatCancel  context.CancelFunc
	heartbeatDone    chan struct{}
	registeredRouter *RouterModel.Router
)

const gatewayRouterRemoveSubject = "gateway.router.remove"

func FetchRouterIndex(sc string, routerURL string, typeValue RouterModel.Type) string {
	url := sc + "://" + routerURL + "/v1/router/id/" + YY.ToString(int(typeValue))
	YY.Debug("FetchRouterIndex: ", url, " type: ", typeValue)
	body, err := http.Get(url)
	if err != nil {
		return ""
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(body.Body)
	YY.Debug("FetchRouterIndex", routerURL, " typeValue: ", typeValue)
	var routerIndex struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.NewDecoder(body.Body).Decode(&routerIndex); err != nil {
		YY.Error("FetchRouterIndex", routerURL, " typevalue: ", typeValue, " err: ", err.Error())
		return ""
	}

	index, err := parseRouterIndex(routerIndex.ID)
	if err != nil {
		YY.Error("FetchRouterIndex", routerURL, " typevalue: ", typeValue, " err: ", err.Error())
		return ""
	}
	return index
}

func parseRouterIndex(raw json.RawMessage) (string, error) {
	var stringID string
	if err := json.Unmarshal(raw, &stringID); err == nil {
		id, err := strconv.ParseUint(stringID, 10, 64)
		if err != nil || id == 0 {
			if err == nil {
				err = errors.New("id must be positive")
			}
			return "", fmt.Errorf("invalid router ID %q: %w", stringID, err)
		}
		return stringID, nil
	}

	var numericID uint64
	if err := json.Unmarshal(raw, &numericID); err != nil {
		return "", fmt.Errorf("invalid router ID: %w", err)
	}
	if numericID == 0 {
		return "", errors.New("invalid router ID: id must be positive")
	}
	return strconv.FormatUint(numericID, 10), nil
}

func BeginRouterService(router *RouterModel.Router, natsURL string, handle func(msg *nats.Msg)) (*nc.NATS, error) {
	if router == nil {
		return nil, errors.New("gateway: router is nil")
	}

	// Start NATS service.
	client := nc.NewClient(natsURL)
	if err := client.Connect(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	natsMu.Lock()
	if natsClient != nil {
		natsMu.Unlock()
		cancel()
		client.Close()
		return nil, errors.New("gateway: router service is already running")
	}
	natsClient = client
	registeredRouter = &RouterModel.Router{ID: router.ID, Type: router.Type}
	heartbeatCancel = cancel
	heartbeatDone = done
	// Start the goroutine before releasing the mutex so StopRouterService can
	// always wait for it, even if shutdown races with startup.
	go heartbeat(ctx, client, router, done)
	natsMu.Unlock()

	if err := subRouterStatus(ctx, client, router, handle); err != nil {
		if stopErr := StopRouterService(); stopErr != nil {
			return nil, errors.Join(err, stopErr)
		}
		return nil, err
	}
	return client, nil
}

func subRouterStatus(ctx context.Context, client *nc.NATS, router *RouterModel.Router, handle func(msg *nats.Msg)) error {
	if client == nil {
		return errors.New("gateway: nats client is nil")
	}

	if _, err := client.Subscribe("gateway."+router.Name+".*", router.Name, func(msg *nats.Msg) {
		handle(msg)
	}); err != nil {
		return fmt.Errorf("gateway: subscribe router status: %w", err)
	}

	if _, err := client.Subscribe("gateway.router.ping", router.Name, func(_ *nats.Msg) {
		// 接收到了 Router 的ping 要返回一下现在gateway 的状态
		select {
		case <-ctx.Done():
			return
		default:
		}
		publishRouterStatus(client, router)
	}); err != nil {
		return fmt.Errorf("gateway: subscribe router ping: %w", err)
	}
	return nil
}

// Heartbeat 每8秒发送一次心跳。
func Heartbeat(router *RouterModel.Router) {
	natsMu.RLock()
	client := natsClient
	natsMu.RUnlock()
	if client == nil {
		return
	}
	heartbeat(context.Background(), client, router, nil)
}

func heartbeat(ctx context.Context, client *nc.NATS, router *RouterModel.Router, done chan<- struct{}) {
	if done != nil {
		defer close(done)
	}

	if router == nil {
		return
	}
	YY.Debug("NATS Heartbeat: ", router.Name)
	ticker := time.NewTicker(8 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			publishRouterStatus(client, router)
		}
	}
}

func publishRouterStatus(client *nc.NATS, router *RouterModel.Router) {
	if client == nil || router == nil {
		return
	}
	router.LastUpdateTime = time.Now().UnixMilli()
	jsonData, err := json.Marshal(router)
	if err != nil {
		YY.Error("NATS router status marshal error:", err)
		return
	}
	if err := client.Publish("gateway.router.status", jsonData); err != nil {
		YY.Error("NATS router status publish error:", err)
	}
}

// StopRouterService stops the heartbeat and releases the NATS connection.
// It is safe to call more than once.
func StopRouterService() error {
	natsMu.Lock()
	cancel := heartbeatCancel
	done := heartbeatDone
	client := natsClient
	router := registeredRouter
	heartbeatCancel = nil
	heartbeatDone = nil
	natsClient = nil
	registeredRouter = nil
	natsMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	if client == nil {
		return nil
	}
	var removalErr error
	if router != nil {
		removalErr = publishRouterRemoval(client, router)
		if removalErr != nil {
			YY.Error("NATS router removal publish error:", removalErr)
		}
	}

	// Closing the owned NATS connection removes its subscriptions and stops the
	// client's internal I/O goroutines without waiting for a network flush.
	client.Close()
	return removalErr
}

func publishRouterRemoval(client *nc.NATS, router *RouterModel.Router) error {
	if client == nil {
		return errors.New("gateway: nats client is nil")
	}
	if router == nil || router.ID == 0 || router.Type <= 0 {
		return errors.New("gateway: router identity is invalid")
	}

	data, err := json.Marshal(router)
	if err != nil {
		return fmt.Errorf("gateway: marshal router removal: %w", err)
	}
	return client.Publish(gatewayRouterRemoveSubject, data)
}

func Push(subj string, data []byte) {
	err := natsClient.Publish(subj, data)
	if err != nil {
		YY.Error("NATS publish error:", err)
		return
	}
}
