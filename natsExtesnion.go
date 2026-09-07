package gateway

import (
	"errors"

	"github.com/yyyear/YY"
)

func Publish(sub string, msg []byte) {
	natsMu.RLock()
	client := natsClient
	natsMu.RUnlock()

	if client == nil {
		return
	}
	e := client.Connect()
	if e != nil {
		YY.Error("---NATS router status publish error:", e.Error())
		return
	}
	if err := client.Publish("gateway.router.status", msg); err != nil {
		YY.Error("NATS router status publish error:", err)
	}
}

// Subscribe 发布一个信息
func Subscribe(subj string, data []byte) error {
	natsMu.RLock()
	client := natsClient
	natsMu.RUnlock()

	if client == nil {
		return errors.New("NATS client is nil")
	}
	err := client.Publish(subj, data)
	if err != nil {
		return errors.New("NATS publish error: " + err.Error())
	}
	return nil
}
