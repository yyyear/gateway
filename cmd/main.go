package main

import (
	"Router/gateway"
	"Router/gateway/websocket"
	"context"
	"errors"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/yyyear/RouterModel"

	"github.com/nats-io/nats.go"
	"github.com/panjf2000/ants/v2"
	"github.com/yyyear/YY"
)

var routerModel *RouterModel.Router

type WSHandle struct {
	//OnOpen(*Conn) error
	//OnMessage(*Conn, Message)
	//OnClose(*Conn, error)
}

type ConnDict map[string]*websocket.Conn

var userConn ConnDict = make(ConnDict, 10000)

func (u *ConnDict) GetConn(token string) *websocket.Conn {
	YY.Debug("---GetConn---", token)
	if conn, ok := (*u)[token]; ok {
		YY.Debug("---GetConn---", token, "  ", conn)
		return conn
	}
	return nil
}

var handlePool, _ = ants.NewPool(10000, ants.WithNonblocking(true))

func (h *WSHandle) OnOpen(c *websocket.Conn) error {
	token := c.Header("token")
	YY.Debug("---OnOpen---", c.RemoteAddr(), c.LocalAddr(), c.Context(), " Header Token:", c.Header("token"))
	if token == "" {
		return errors.New("token is empty")
	}
	if conn, ok := userConn[token]; ok {
		err := conn.Write(1, []byte("顶号了!"))
		if err != nil {
			return err
		}
		// 退出连接
		err = conn.Close()
		if err != nil {
			return err
		}
		routerModel.ConnectNum -= 1
	}
	routerModel.ConnectNum += 1
	userConn[token] = c
	return nil
}
func (h *WSHandle) OnMessage(c *websocket.Conn, msg *websocket.Message) {
	handlePool.Submit(func() {
		sub := "msg." + routerModel.Name + "." + c.Header("token")
		gateway.Push(sub, msg.Data)
	})
}
func (h *WSHandle) OnClose(c *websocket.Conn, e error) {
	routerModel.ConnectNum -= 1
}

func main() {
	// 从网关获取一个有效的ID
	index := gateway.FetchRouterIndex("http", "127.0.0.1:8899", RouterModel.GameGateway)
	id, err := strconv.ParseUint(index, 10, 64)
	if err != nil || id == 0 {
		YY.Error("failed to fetch a valid gateway ID")
		return
	}

	routerModel = RouterModel.NewRouter(RouterModel.GameGateway, id, "192.168.0.240:8080", "wss")
	servers := []string{
		"nats://127.0.0.1:1224",
		"nats://127.0.0.1:1223",
		"nats://local.cardsvault.net:4222",
	}

	err = gateway.BeginRouterService(routerModel, strings.Join(servers, ","), func(msg *nats.Msg) {
		YY.Debug("---", msg.Subject)
		_ = handlePool.Submit(func() {
			g, token := RouterModel.Splite(msg.Subject)
			conn := userConn.GetConn(token)
			if conn != nil && conn.IsOpen() {
				_ = conn.Write(1, msg.Data)
			}
			YY.Debug("--Received message--", msg, "   cutLast:", g, " ", token)
		})
	})
	if err != nil {
		YY.Error("failed to start router service:", err)
		return
	}
	ws := websocket.NewServerWithHandler(routerModel.Address, &WSHandle{})
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()

		if err := ws.Stop(shutdownCtx); err != nil && !errors.Is(err, websocket.ErrServerNotRunning) {
			YY.Error("websocket shutdown error:", err)
		}
		if err := gateway.StopRouterService(); err != nil {
			YY.Error("router service shutdown error:", err)
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	err = ws.Run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		YY.Error("websocket run error:", err)
	}
	YY.Info("websocket server stopped")
}
