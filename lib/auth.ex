defmodule FirebaseAdminEx.Auth do
  alias FirebaseAdminEx.{Request, Response, Errors}
  alias FirebaseAdminEx.Auth.ActionCodeSettings

  @auth_endpoint "https://www.googleapis.com/identitytoolkit/v3/relyingparty/"
  @auth_endpoint_account "https://identitytoolkit.googleapis.com/v1/projects/"
  @auth_scope "https://www.googleapis.com/auth/cloud-platform"

  @doc """
  Get a user's info by UID
  """
  @spec get_user(String.t(), String.t() | nil) :: tuple()
  def get_user(uid, client_email \\ nil), do: get_user(:localId, uid, client_email)

  @doc """
  Get a user's info by phone number
  """
  @spec get_user_by_phone_number(String.t(), String.t() | nil) :: tuple()
  def get_user_by_phone_number(phone_number, client_email \\ nil),
    do: get_user(:phone_number, phone_number, client_email)

  @doc """
  Get a user's info by email
  """
  @spec get_user_by_email(String.t(), String.t() | nil) :: tuple()
  def get_user_by_email(email, client_email \\ nil),
    do: get_user(:email, email, client_email)

  defp get_user(key, value, client_email),
    do: do_request("getAccountInfo", %{key => value}, client_email)

  @doc """
  Delete an existing user by UID
  """
  @spec delete_user(String.t(), String.t() | nil) :: tuple()
  def delete_user(uid, client_email \\ nil),
    do: do_request("deleteAccount", %{localId: uid}, client_email)
	
	
  @doc """
  update a user
  """
  def update_user(%{"idToken" => idToken, "displayName" => displayName, "localId" => localId},
        client_email \\ nil
      ),
      do:
        do_request(
          "setAccountInfo",
          %{:idToken => idToken, :displayName => displayName, :localId => localId, :returnSecureToken => true},
          client_email
        )	


	@doc """
	change password
	"""
	def change_password(%{"idToken" => idToken, "password" => password, "localId" => localId},
	      client_email \\ nil
	    ),
	    do:
	      do_request(
	        "setAccountInfo",
	        %{:idToken => idToken, :password => password, :localId => localId, :returnSecureToken => true},
	        client_email
	      )	

	@doc """
	change password
	"""
	def change_email(%{"idToken" => idToken, "email" => email, "localId" => localId},
	      client_email \\ nil
	    ),
	    do:
	      do_request(
	        "setAccountInfo",
	        %{:idToken => idToken, email => email, :localId => localId, :returnSecureToken => true},
	        client_email
	      )	


  # TODO: Add other commands:
  # list_users
  # import_users
  
  @doc """
  Create an anonymous user
  """
  @spec create_anonymous_user(String.t() | nil) :: tuple()
  def create_anonymous_user(client_email \\ nil),
      do:
        do_request(
          "signupNewUser",
          %{:returnSecureToken => true},
          client_email
        )

  @doc """
  Create an email/password user
  """
  @spec create_email_password_user(map, String.t() | nil) :: tuple()
  def create_email_password_user(
        %{"email" => email, "password" => password},
        client_email \\ nil
      ),
      do:
        do_request(
          "signupNewUser",
          %{:email => email, :password => password, :returnSecureToken => true},
          client_email
        )

  @doc """
  Generates the email action link for sign-in flows, using the action code settings provided
  """
  @spec generate_sign_in_with_email_link(ActionCodeSettings.t(), String.t(), String.t()) :: tuple()
  def generate_sign_in_with_email_link(action_code_settings, client_email, project_id) do
    with {:ok, action_code_settings} <- ActionCodeSettings.validate(action_code_settings) do
      do_request("accounts:sendOobCode", action_code_settings, client_email, project_id)
    end
  end
  
  
  
  @doc """
  Generates the email for password reset
  """
  def generate_reset_password_email(%{"email" => email},
        client_email \\ nil
      ),
      do:
        do_request(
          "getOobConfirmationCode",
          %{:email => email, "requestType" => "PASSWORD_RESET"},
          client_email
        )
		
	@doc """
	Generates the email for confirmation
	"""
	def generate_confirmation_email(%{"token" => token},
	      client_email \\ nil
	    ),
	    do:
	      do_request(
	        "getOobConfirmationCode",
	        %{:idToken => token, "requestType" => "VERIFY_EMAIL"},
	        client_email
	      )	
  
  @doc """
  Verifies OOB Code
  """
  def verify_password_code(%{"oobCode" => oob_code},
        client_email \\ nil
      ),
      do:
        do_request(
          "resetPassword",
          %{:oobCode => oob_code},
          client_email
        )

	@doc """
	confirms and performs password reset
	"""
	def confirm_password_reset(%{"oobCode" => oob_code, "newPassword" => password},
	      client_email \\ nil
	    ),
	    do:
	      do_request(
	        "resetPassword",
	        %{:oobCode => oob_code, :newPassword => password},
	        client_email
	      )

	@doc """
	Verifies signs user in with email and password
	"""
	def sign_in_with_email_and_password(%{"email" => email, "password" => password},
        client_email \\ nil
      ),
      do:
        do_request(
          "verifyPassword",
          %{:email => email, :password => password, :returnSecureToken => true},
          client_email
        )
  
  defp do_request(url_suffix, payload, client_email, project_id) do
    with {:ok, response} <-
           Request.request(
             :post,
             "#{@auth_endpoint_account}#{project_id}/#{url_suffix}",
             payload,
             auth_header(client_email)
           ),
         {:ok, body} <- Response.parse(response) do
      {:ok, body}
    else
      {:error, error} -> raise Errors.ApiError, Kernel.inspect(error)
    end
  end

  defp do_request(url_suffix, payload, client_email) do
    with {:ok, response} <-
           Request.request(
             :post,
             @auth_endpoint <> url_suffix,
             payload,
             auth_header(client_email)
           ),
         {:ok, body} <- Response.parse(response) do
      {:ok, body}
    else
      {:error, error} -> raise Errors.ApiError, Kernel.inspect(error)
    end
  end

  defp auth_header(nil) do
    {:ok, token} = Goth.Token.for_scope(@auth_scope)

    do_auth_header(token.token)
  end

  defp auth_header(client_email) do
    {:ok, token} = Goth.Token.for_scope({client_email, @auth_scope})

    do_auth_header(token.token)
  end

  defp do_auth_header(token) do
    %{"Authorization" => "Bearer #{token}"}
  end
end
