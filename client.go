package microservice_example

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
