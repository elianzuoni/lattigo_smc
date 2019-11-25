package services

import (
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

type Client struct {
	*onet.Client
	clientID   string
	entryPoint *network.ServerIdentity

	//
}

func NewLattigoSMCClient(entryPoint *network.ServerIdentity, clientID string) *Client {
	client := &Client{
		Client:     onet.NewClient(suites.MustFind("Ed25519"), ServiceName),
		clientID:   clientID,
		entryPoint: entryPoint,
	}

	return client
}

func (c *Client) SendSumQuery() {

}

func (c *Client) SendWriteQuery() {

}

func (c *Client) SendMultiplyQuery() {

}
