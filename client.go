package microservice_example

import "log"

type Client struct {
	ID        string
	ExpiredAt int64
	Code      string
	Secret    string
	Domain    string
	UserID    string
	Access    string
	Refresh   string
	Data      string
}

func (c *Client) GetID() string {
	return c.ID
}
func (c *Client) GetSecret() string {
	return c.Secret
}
func (c *Client) GetDomain() string {
	return c.Domain
}
func (c *Client) GetUserID() string {
	return c.UserID
}

func (c *Client) VerifyPassword(password string) (ok bool) {
	if password == "" {
		log.Print("TODO Wrap client interface for PKCE. Empty secret")
		ok = true
	} else {
		ok = password == c.Secret
	}
	return
}
