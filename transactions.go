package steranko

// SigninTransaction includes all of the information that MUST be posted
// to Sterenko in order to sign in to the system.
type SigninTransaction struct {
	Username      string `json:"username"`      // public username for this person
	Password      string `json:"password"`      // private (hashed?) password for this person
	TwoFactorCode string `json:"twoFactorCode"` // [Optional] 2FA code to send to the 2FA plugin
}

// SigninResponse includes all the information returned by Steranko
// after a signin request.
type SigninResponse struct {
	Username     string
	JWT          string
	ErrorMessage string
	Error        error
}

type RequestPasswordResetTransaction struct {
	Username string `json:"username"` // public username of the person requesting the reset.
}

type RequestPasswordResetResponse struct {
}

type UpdatePasswordTransaction struct {
	Username    string `json:"username"`
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

type UpdatePasswordResponse struct {
}
