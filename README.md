# API Documentation for Authentication and Client Management With Keycloak

## Table of Contents

- [Keycloak API Operations](#keycloak-api-operations)
  - [1. Get Refresh Token](#1-get-refresh-token)
  - [2. Reset Password in Keycloak](#2-reset-password-in-keycloak)
  - [3. Enable/Disable MFA](#3-enabledisable-mfa)
  - [4. Reset MFA](#4-reset-mfa)
  - [5. Create New Realm](#5-create-new-realm)
  - [6. Create Client in Keycloak](#6-create-client-in-keycloak)
  - [7. Create User in the Realm](#7-create-user-in-the-realm)
  - [8. Role Management](#8-role-management)
    - [8.1 Create Custom Role](#81-create-custom-role)
    - [8.2 Get Custom Role ID](#82-get-custom-role-id)
    - [8.3 Get Realm-Management Client ID](#83-get-realm-management-client-id)
    - [8.4 Get Realm-Admin Role](#84-get-realm-admin-role)
    - [8.5 Assign Realm-Admin Role to User](#85-assign-realm-admin-role-to-user)
    - [8.6 Assign Custom Role to User](#86-assign-custom-role-to-user)
- [Authentication Flow](#authentication-flow)
  - [Login with Keycloak](#login-with-keycloak)
  - [Middleware Authentication](#middleware-authentication)
- [API Endpoints and Code](#api-endpoints-and-code)
  - [1. User Login (`auth.controller.js`)](#1-user-login-authcontrollerjs)
  - [2. Enable/Disable MFA (`auth.controller.js`)](#2-enabledisable-mfa-authcontrollerjs)
  - [3. Reset MFA (`auth.controller.js`)](#3-reset-mfa-authcontrollerjs)
  - [4. Get Keycloak Client ID by Email or Username (`user.controller.js`)](#4-get-keycloak-client-id-by-email-or-username-usercontrollerjs)
  - [5. Add New Client (`client.controller.js`)](#5-add-new-client-clientcontrollerjs)
- [Middleware](#middleware)
  - [`isAuthenticated` (`auth.middleware.js`)](#isauthenticated-authmiddlewarejs)
- [Data Models](#data-models)
  - [`Users` (`users.model.js`)](#users-usersmodeljs)
  - [`Clients` (`client.model.js`)](#clients-clientmodeljs)
  - [`Role_Has_Permission` (`role_has_permission.model.js`)](#role_has_permission-role_has_permissionmodeljs)
- [Dependencies](#dependencies)
- [Environment Variables](#environment-variables)
- [Notes](#notes)

## Keycloak API Operations

This section outlines the Keycloak API endpoints used for managing authentication, users, clients, and roles. All requests require a valid Keycloak admin access token in the `Authorization` header (`Bearer <TOKEN>`). Replace `${KEYCLOAK_BASE_URL}` with your Keycloak instance URL (e.g., `https://auth.example.com`) and `${KEYCLOAK_BASE_ADMIN_URL}` with the admin endpoint (e.g., `https://auth.example.com/admin`).

### 1. Get Refresh Token

**Description**: Obtains a new access token using a refresh token.

**Endpoint**: `POST ${KEYCLOAK_BASE_URL}/realms/${REALM}/protocol/openid-connect/token`

**Request**:

- **Headers**:
  - `Content-Type`: `application/x-www-form-urlencoded`
- **Body** (Form URL Encoded):

  ```json
  {
    "grant_type": "refresh_token", // Fixed value to indicate refresh token grant type
    "client_id": "<KEYCLOAK_CLIENT_ID>", // The client ID configured in Keycloak
    "refresh_token": "<KEYCLOAK_REFRESH_TOKEN>" // The refresh token issued to the client
  }
  ```

**Response**:

- **Success** (200 OK):

  ```json
  {
    "access_token": "<NEW_ACCESS_TOKEN>",
    "expires_in": 3600,
    "refresh_token": "<NEW_REFRESH_TOKEN>",
    "token_type": "Bearer",
    "scope": "profile email"
  }
  ```

- **Error**:
  - 400 Bad Request: Invalid `CLIENT_ID` or `REFRESH_TOKEN`
  - 401 Unauthorized: Invalid credentials

**Notes**:

- Used to refresh an expired access token without requiring the user to re-authenticate.
- Ensure the `REFRESH_TOKEN` is valid and not expired.

### 2. Reset Password in Keycloak

**Description**: Resets the password for a specific user in the Keycloak realm.

**Endpoint**: `PUT ${KEYCLOAK_BASE_ADMIN_URL}/realms/${REALM_NAME}/users/${USER_ID}/reset-password`

**Request**:

- **Headers**:
  - `Authorization`: `Bearer <KEYCLOAK_ADMIN_ACCESS_TOKEN>`
  - `Content-Type`: `application/json`
- **Body**:

  ```json
  {
    "type": "password", // Fixed value indicating password credential type
    "value": "<NEW_PASSWORD>", // The new password for the user
    "temporary": false // If true, user must change password on next login; if false, password is set permanently
  }
  ```

**Response**:

- **Success** (204 No Content): Password reset successfully
- **Error**:
  - 400 Bad Request: Invalid password format
  - 401 Unauthorized: Invalid admin token
  - 404 Not Found: User not found

**Notes**:

- Requires admin privileges in Keycloak.
- The `temporary` flag controls whether the user must update their password upon next login.

### 3. Enable/Disable MFA

**Description**: Enables or disables Multi-Factor Authentication (MFA) for a user by adding or removing the `CONFIGURE_TOTP` required action.

**Endpoint**: `PUT ${KEYCLOAK_BASE_ADMIN_URL}/realms/${REALM}/users/${KEYCLOAK_USER_ID}`

**Request**:

- **Headers**:
  - `Authorization`: `Bearer <KEYCLOAK_ADMIN_ACCESS_TOKEN>`
  - `Content-Type`: `application/json`
- **Body**:

  ```json
  {
    "requiredActions": ["CONFIGURE_TOTP"] // Adds TOTP configuration requirement for enabling MFA
  }
  ```

**Response**:

- **Success** (204 No Content): MFA configuration updated
- **Error**:
  - 401 Unauthorized: Invalid admin token
  - 404 Not Found: User or realm not found

**Notes**:

- To disable MFA, remove `CONFIGURE_TOTP` from `requiredActions` (see Reset MFA below).
- Requires fetching the current user’s `requiredActions` to avoid overwriting other actions.

### 4. Reset MFA

**Description**: Resets MFA for a user by deleting existing OTP credentials and re-adding the `CONFIGURE_TOTP` required action to trigger re-enrollment.

**Steps**:

1. **Get CredentialsEndpoint**: `GET ${KEYCLOAK_BASE_ADMIN_URL}/users/${KEYCLOAK_USER_ID}/credentials`

   - **Headers**:
     - `Authorization`: `Bearer <KEYCLOAK_ADMIN_ACCESS_TOKEN>`
   - **Response** (200 OK):

     ```json
     [
       {
         "id": "<CREDENTIAL_ID>",
         "type": "otp",
         "createdDate": 16987654321,
         "credentialData": {}
       }
       // Other credentials
     ]
     ```

   - **Purpose**: Retrieves all credentials for the user to identify OTP credentials.

2. **Delete OTP CredentialsEndpoint**: `DELETE ${KEYCLOAK_BASE_ADMIN_URL}/users/${KEYCLOAK_USER_ID}/credentials/${OTPCRED_ID}`

   - **Headers**:
     - `Authorization`: `Bearer <KEYCLOAK_ADMIN_ACCESS_TOKEN>`
   - **Response**:
     - **Success** (204 No Content): OTP credential deleted
     - **Error**:
       - 401 Unauthorized: Invalid admin token
       - 404 Not Found: Credential not found
   - **Purpose**: Removes existing OTP credentials to reset MFA.

3. **Add CONFIGURE_TOTP to Required ActionsEndpoint**: `PUT ${KEYCLOAK_BASE_ADMIN_URL}/users/${KEYCLOAK_USER_ID}`

   - **Headers**:
     - `Authorization`: `Bearer <KEYCLOAK_ADMIN_ACCESS_TOKEN>`
     - `Content-Type`: `application/json`
   - **Body**:

     ```json
     {
       "requiredActions": ["CONFIGURE_TOTP"] // Ensures TOTP setup is required on next login
     }
     ```

   - **Response**:
     - **Success** (204 No Content): Required actions updated
     - **Error**:
       - 401 Unauthorized: Invalid admin token
       - 404 Not Found: User not found
   - **Purpose**: Triggers MFA re-enrollment by adding `CONFIGURE_TOTP`.

**Notes**:

- Fetch the user’s current `requiredActions` before updating to avoid overwriting other actions.
- Requires admin privileges.

### 5. Create New Realm

**Description**: Creates a new realm in Keycloak.

**Endpoint**: `POST ${KEYCLOAK_BASE_ADMIN_URL}/realms`

**Request**:

- **Headers**:
  - `Authorization`: `Bearer <KEYCLOAK_ADMIN_ACCESS_TOKEN>`
  - `Content-Type`: `application/json`
- **Body**:

  ```json
  {
    "realm": "<REALM_NAME>", // Unique name for the new realm
    "enabled": true, // Enables the realm for immediate use
    "attributes": {
      "displayName": "<DISPLAY_NAME>" // Display name for the realm in Keycloak UI
    }
  }
  ```

**Response**:

- **Success** (201 Created): Realm created successfully
- **Error**:
  - 400 Bad Request: Invalid realm name or duplicate realm
  - 401 Unauthorized: Invalid admin token

**Notes**:

- Requires Keycloak admin privileges with realm creation permissions.
- The `displayName` is shown in the Keycloak admin console.

### 6. Create Client in Keycloak

**Description**: Creates a new client in a Keycloak realm for authentication purposes.

**Endpoint**: `POST ${KEYCLOAK_BASE_ADMIN_URL}/realms/${REALM}/clients`

**Request**:

- **Headers**:
  - `Authorization`: `Bearer <KEYCLOAK_ADMIN_ACCESS_TOKEN>`
  - `Content-Type`: `application/json`
- **Body**:

  ```json
  {
    "clientId": "<KEYCLOAK_CLIENT_ID>", // Unique client ID as a string
    "enabled": true, // If true, client is active; if false, client is inactive
    "protocol": "openid-connect", // Fixed value for OpenID Connect protocol
    "rootUrl": "<ROOT_URL>", // Base URL for the client application
    "baseUrl": "<BASE_URL>", // Base path for the client
    "redirectUris": ["<URL1>", "<URL2>"], // Array of valid redirect URIs after login
    "webOrigins": ["<URL1>", "<URL2>"], // Array of allowed web origins for CORS
    "adminUrl": "<ADMIN_URL>", // URL for admin callbacks
    "publicClient": true // If true, no client secret is required; if false, a client secret is generated
  }
  ```

**Response**:

- **Success** (201 Created): Client created successfully
- **Error**:
  - 400 Bad Request: Invalid or duplicate `CLIENT_ID`
  - 401 Unauthorized: Invalid admin token
  - 403 Forbidden: Insufficient permissions

**Notes**:

- If `publicClient` is `false`, retrieve the client secret from Keycloak after enabling authentication.
- Ensure `redirectUris` and `webOrigins` are valid URLs.

### 7. Create User in the Realm

**Description**: Creates a new user in a Keycloak realm with specified credentials.

**Endpoint**: `POST ${KEYCLOAK_BASE_ADMIN_URL}/realms/${REALM}/users`

**Request**:

- **Headers**:
  - `Authorization`: `Bearer <KEYCLOAK_ADMIN_ACCESS_TOKEN>`
  - `Content-Type`: `application/json`
- **Body**:

  ```json
  {
    "username": "<USERNAME>", // Unique username for the user
    "email": "<EMAIL_ADDRESS>", // User's email address
    "firstName": "<FIRST_NAME>", // User's first name
    "lastName": "<LAST_NAME>", // User's last name
    "enabled": true, // If true, user is active; if false, user is inactive
    "credentials": [
      {
        "type": "password", // Fixed value for password credential
        "value": "<PASSWORD>", // User's initial password
        "temporary": false // If true, user must change password on first login; if false, password is permanent
      }
    ]
  }
  ```

**Response**:

- **Success** (201 Created): User created successfully
- **Error**:
  - 400 Bad Request: Invalid username, email, or password
  - 409 Conflict: Username or email already exists
  - 401 Unauthorized: Invalid admin token

**Notes**:

- Requires admin privileges in the realm.
- The `temporary` flag prompts the user to reset their password on first login.

### 8. Role Management

**Description**: Manages roles in Keycloak, including creating custom roles and assigning them to users.

#### 8.1 Create Custom Role

**Endpoint**: `POST ${KEYCLOAK_BASE_ADMIN_URL}/realms/${REALM}/clients/${KEYCLOAK_CLIENT_UUID}/roles`

**Request**:

- **Headers**:
  - `Authorization`: `Bearer <KEYCLOAK_ADMIN_ACCESS_TOKEN>`
  - `Content-Type`: `application/json`
- **Body**:

  ```json
  {
    "name": "<ROLE_NAME>", // Unique name for the role
    "description": "<ROLE_DESCRIPTION>" // Description of the role
  }
  ```

**Response**:

- **Success** (201 Created): Role created successfully
- **Error**:
  - 400 Bad Request: Invalid or duplicate role name
  - 401 Unauthorized: Invalid admin token

**Notes**:

- The `KEYCLOAK_CLIENT_UUID` is the UUID of the client in Keycloak, not the `CLIENT_ID`.

#### 8.2 Get Custom Role ID

**Endpoint**: `GET ${KEYCLOAK_BASE_ADMIN_URL}/realms/${REALM}/clients/${KEYCLOAK_CLIENT_UUID}/roles/${ROLE}`

**Request**:

- **Headers**:
  - `Authorization`: `Bearer <KEYCLOAK_ADMIN_ACCESS_TOKEN>`
- **Response** (200 OK):

  ```json
  {
    "id": "<ROLE_ID>",
    "name": "<ROLE_NAME>",
    "description": "<ROLE_DESCRIPTION>",
    "clientRole": true
  }
  ```

- **Error**:
  - 404 Not Found: Role not found
  - 401 Unauthorized: Invalid admin token

**Notes**:

- Use the returned `ROLE_ID` for role assignments.

#### 8.3 Get Realm-Management Client ID

**Endpoint**: `GET ${KEYCLOAK_BASE_ADMIN_URL}/realms/${REALM}/clients?clientId=realm-management`

**Request**:

- **Headers**:
  - `Authorization`: `Bearer <KEYCLOAK_ADMIN_ACCESS_TOKEN>`
- **Response** (200 OK):

  ```json
  [
    {
      "id": "<REALM_MGMT_CLIENT_ID>",
      "clientId": "realm-management",
      "enabled": true
    }
  ]
  ```

- **Error**:
  - 401 Unauthorized: Invalid admin token

**Notes**:

- The `realm-management` client contains realm-level roles like `realm-admin`.

#### 8.4 Get Realm-Admin Role

**Endpoint**: `GET ${KEYCLOAK_BASE_ADMIN_URL}/realms/${REALM}/clients/${REALM_MGMT_CLIENT_ID}/roles/realm-admin`

**Request**:

- **Headers**:
  - `Authorization`: `Bearer <KEYCLOAK_ADMIN_ACCESS_TOKEN>`
- **Response** (200 OK):

  ```json
  {
    "id": "<REALM_ADMIN_ROLE_ID>",
    "name": "realm-admin",
    "description": "Realm administrator role"
  }
  ```

- **Error**:
  - 404 Not Found: Role not found
  - 401 Unauthorized: Invalid admin token

**Notes**:

- Use the `REALM_ADMIN_ROLE_ID` to assign the `realm-admin` role to users.

#### 8.5 Assign Realm-Admin Role to User

**Endpoint**: `POST ${KEYCLOAK_BASE_ADMIN_URL}/realms/${REALM}/users/${NEW_KEYCLOAK_USER_ID}/role-mappings/clients/${REALM_MGMT_CLIENT_ID}`

**Request**:

- **Headers**:
  - `Authorization`: `Bearer <KEYCLOAK_ADMIN_ACCESS_TOKEN>`
  - `Content-Type`: `application/json`
- **Body**:

  ```json
  [
    {
      "id": "<REALM_ADMIN_ROLE_ID>", // ID of the realm-admin role
      "name": "realm-admin" // Name of the role
    }
  ]
  ```

**Response**:

- **Success** (204 No Content): Role assigned successfully
- **Error**:
  - 400 Bad Request: Invalid role or user
  - 401 Unauthorized: Invalid admin token
  - 404 Not Found: User or client not found

**Notes**:

- Grants the user administrative privileges for the realm.

#### 8.6 Assign Custom Role to User

**Endpoint**: `POST ${KEYCLOAK_BASE_ADMIN_URL}/realms/${REALM}/users/${NEW_KEYCLOAK_USER_ID}/role-mappings/clients/${KEYCLOAK_CLIENT_UUID}`

**Request**:

- **Headers**:
  - `Authorization`: `Bearer <KEYCLOAK_ADMIN_ACCESS_TOKEN>`
  - `Content-Type`: `application/json`
- **Body**:

  ```json
  [
    {
      "id": "<ROLE_ID>", // ID of the custom role
      "name": "<ROLE_NAME>" // Name of the custom role
    }
  ]
  ```

**Response**:

- **Success** (204 No Content): Role assigned successfully
- **Error**:
  - 400 Bad Request: Invalid role or user
  - 401 Unauthorized: Invalid admin token
  - 404 Not Found: User or client not found

**Notes**:

- Assigns a client-specific custom role to the user.

## Authentication Flow

### Login with Keycloak

- Use the Keycloak URL `https://<KEYCLOAK_URL>/realms/:REALM_NAME/protocol/openid-connect/token` to obtain an access token.
- The access token must be included in the `Authorization` header as `Bearer <TOKEN>` for all subsequent API requests.

### Middleware Authentication

- The `isAuthenticated` middleware verifies the Keycloak token using the `jwks-rsa` library to fetch the public key from the Keycloak issuer's JSON Web Key Set (JWKS) endpoint (`${KEYCLOAK_ISSUER}/protocol/openid-connect/certs`).
- If the token is valid, the decoded user information is attached to `req.user` for downstream processing.

## API Endpoints and Code

### 1. User Login (`auth.controller.js`)

**Endpoint**: `POST /auth/login`

**Description**: Authenticates a user using a Keycloak access token and creates or updates the user in the database.

**Code**:

```javascript
const loginUser = async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.replace("Bearer ", "");

    if (!token) {
      return handleResponse(
        res,
        false,
        statusCodes.UNAUTHORIZED,
        "No token provided"
      );
    }

    let decoded;
    try {
      decoded = jwt.decode(token);
    } catch (decodeError) {
      return handleResponse(
        res,
        false,
        statusCodes.UNAUTHORIZED,
        "Invalid token format"
      );
    }

    if (!decoded || !decoded.sub) {
      return handleResponse(
        res,
        false,
        statusCodes.UNAUTHORIZED,
        "Invalid Keycloak token"
      );
    }

    const keycloakId = decoded.sub;
    const email = decoded.email?.toLowerCase();
    const username = decoded.preferred_username;
    const firstName = decoded.given_name || "";
    const lastName = decoded.family_name || "";
    const sessionId = decoded.session_state;
    const clientRoles = decoded.resource_access || {};
    const currentClientKey = decoded.azp;

    const roleName =
      currentClientKey && clientRoles[currentClientKey]?.roles?.[0]
        ? clientRoles[currentClientKey].roles[0]
        : null;

    let user = await AuthModel.findOne({ keycloak_user_id: keycloakId });

    if (!user && email) {
      user = await AuthModel.findOne({ email });
    }

    if (!user) {
      try {
        user = await AuthModel.create({
          keycloak_user_id: keycloakId,
          email,
          username,
          firstName,
          lastName,
          session_id: sessionId,
          client_roles: clientRoles,
          roleName: roleName || null,
          isActive: true,
          isVerified: true,
          isLoggedIn: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
      } catch (createError) {
        console.error("Error creating user:", createError);
        return handleResponse(
          res,
          false,
          statusCodes.INTERNAL_SERVER_ERROR,
          `Failed to create user: ${createError.message}`
        );
      }
    }

    let roleObject = null;
    if (roleName) {
      roleObject = await rolesModel.findOne({ name: roleName });
      if (!roleObject) {
        roleObject = await rolesModel.create({ name: roleName });
      }
    }

    user.role = roleObject?._id || null;
    user.roleName = roleName || null;
    user.client_roles = clientRoles;
    user.session_id = sessionId;
    user.username = username;
    user.last_login_at = new Date();
    user.updatedAt = new Date();
    user.isLoggedIn = true;
    user.keycloak_client_id = currentClientKey || user.keycloak_client_id;

    let ipAddress =
      req.headers["x-forwarded-for"] || req.connection.remoteAddress;
    if (typeof ipAddress === "string" && ipAddress.startsWith("::ffff:")) {
      ipAddress = ipAddress.substring(7);
    }

    if (ipAddress && user.ipAddress !== ipAddress) {
      user.ipAddress = ipAddress;
    }

    await user.save();

    if (!user.isActive) {
      return handleResponse(
        res,
        false,
        statusCodes.UNAUTHORIZED,
        "User is not active. Contact Admin"
      );
    }

    const otpauthUrl = `otpauth://totp/${APP_NAME}:${user.email}?secret=${user.AuthSecret}&issuer=${APP_NAME}`;

    await user.populate("modules");

    let permissions = [];
    if (roleObject?._id) {
      const rolePerm = await roleHasPermissionModel
        .findOne({ roleId: roleObject._id })
        .populate("permissionId", "name")
        .lean();

      permissions =
        rolePerm?.permissionId?.map((perm) => perm.name).filter(Boolean) || [];
    }

    const user_has_module_permissions = await userHasModulePermissionModel
      .find({ user_id: user._id })
      .populate("moduleId", "name")
      .populate("permissionIds", "name");

    const userModulePermissions = user_has_module_permissions.map((p) => ({
      moduleName: p.moduleId?.name,
      permissions: p.permissionIds.map((perm) => perm.name).filter(Boolean),
    }));

    res.setHeader("Authorization", `Bearer ${token}`);
    return handleResponse(res, true, statusCodes.OK, "Login Successful..!", {
      qrCodeURL: otpauthUrl,
      keycloakUserId: decoded.sub,
      accessToken: token,
      userId: user._id,
      keycloakClientId: user.keycloak_client_id,
      role: user.roleName,
      roleName: user.roleName,
      username: user.firstName + " " + user.lastName,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      isVerified: user.isVerified,
      isActive: user.isActive,
      isMFAEnabled: user.isMFAEnabled,
      createdAt: user.createdAt,
      ipAddress: user.ipAddress,
      modules: user.modules?.map((m) => ({
        id: m._id,
        name: m.name,
      })),
      session_id: user.session_id,
      keycloak_username: user.username,
      client_roles: user.client_roles || {},
      permissions,
      userModulePermissions,
    });
  } catch (error) {
    console.error("Login Error:", error);
    return handleResponse(
      res,
      false,
      statusCodes.INTERNAL_SERVER_ERROR,
      error.message
    );
  }
};
```

**Request**:

- **Headers**:
  - `Authorization`: `Bearer <KEYCLOAK_ACCESS_TOKEN>`
- **Body**: None

**Response**:

- **Success** (200 OK):

  ```json
  {
    "success": true,
    "status": 200,
    "message": "Login Successful..!",
    "data": {
      "qrCodeURL": "otpauth://totp/MyApp:user@example.com?secret=<SECRET>&issuer=MyApp",
      "keycloakUserId": "<KEYCLOAK_USER_ID>",
      "accessToken": "<KEYCLOAK_ACCESS_TOKEN>",
      "userId": "<MONGO_USER_ID>",
      "keycloakClientId": "<KEYCLOAK_CLIENT_ID>",
      "role": "<ROLE_NAME>",
      "roleName": "<ROLE_NAME>",
      "username": "<FIRST_NAME LAST_NAME>",
      "email": "<EMAIL>",
      "firstName": "<FIRST_NAME>",
      "lastName": "<LAST_NAME>",
      "isVerified": true,
      "isActive": true,
      "isMFAEnabled": false,
      "createdAt": "<TIMESTAMP>",
      "ipAddress": "<IP_ADDRESS>",
      "modules": [{ "id": "<MODULE_ID>", "name": "<MODULE_NAME>" }],
      "session_id": "<SESSION_ID>",
      "keycloak_username": "<USERNAME>",
      "client_roles": {},
      "permissions": ["PERMISSION1", "PERMISSION2"],
      "userModulePermissions": [
        { "moduleName": "<MODULE_NAME>", "permissions": ["PERM1", "PERM2"] }
      ]
    }
  }
  ```

- **Error**:
  - 401 Unauthorized: "No token provided", "Invalid token format", "Invalid Keycloak token", or "User is not active. Contact Admin"
  - 500 Internal Server Error: "Failed to create user: &lt;ERROR_MESSAGE&gt;" or other server errors

**Logic**:

- Validates the Keycloak token and decodes it to extract `sub`, `email`, `preferred_username`, `given_name`, `family_name`, `session_state`, `resource_access`, and `azp`.
- Checks for an existing user by `KEYCLOAK_USER_ID` or `EMAIL`. Creates a new user if none exists.
- Updates user details (e.g., `role`, `session_id`, `ipAddress`, `last_login_at`).
- Fetches role permissions and user module permissions.
- Generates a TOTP QR code URL for MFA setup.
- Returns user details, permissions, and module information.

### 2. Enable/Disable MFA (`auth.controller.js`)

**Endpoint**: `POST /auth/enable-disable-mfa`

**Description**: Enables or disables MFA for a user in Keycloak and updates the user's `isMFAEnabled` status.

**Code**:

```javascript
const enableDisableMFAKeycloak = async (req, res) => {
  try {
    const { keycloak_user_id, status } = req.body;
    const bearerToken = req.headers.authorization?.split(" ")[1];

    if (
      !keycloak_user_id ||
      bearerToken === undefined ||
      typeof status !== "boolean"
    ) {
      return handleResponse(
        res,
        false,
        statusCodes.BAD_REQUEST,
        "Missing KEYCLOAK_USER_ID, status or BEARER_TOKEN"
      );
    }

    const headers = {
      Authorization: `Bearer ${bearerToken}`,
      "Content-Type": "application/json",
    };

    const user = await usersModel.findOne({ keycloak_user_id });
    if (!user) {
      return handleResponse(
        res,
        false,
        statusCodes.NOT_FOUND,
        "User not found"
      );
    }

    if (status) {
      // ENABLE MFA
      if (user.isMFAEnabled === true) {
        return handleResponse(
          res,
          false,
          statusCodes.BAD_REQUEST,
          "MFA is already enabled for the user..!"
        );
      }

      await axios.put(
        `${KEYCLOAK_BASE_ADMIN_URL}/users/${keycloak_user_id}`,
        { requiredActions: ["CONFIGURE_TOTP"] },
        { headers }
      );

      await usersModel.findOneAndUpdate(
        { keycloak_user_id },
        { isMFAEnabled: true },
        { new: true }
      );

      return handleResponse(
        res,
        true,
        statusCodes.OK,
        "MFA enabled Successfully..!"
      );
    } else {
      // DISABLE MFA
      if (user.isMFAEnabled === false) {
        return handleResponse(
          res,
          false,
          statusCodes.BAD_REQUEST,
          "MFA is already disabled for the user..!"
        );
      }

      // 1. Delete OTP credential
      const credRes = await axios.get(
        `${KEYCLOAK_BASE_ADMIN_URL}/users/${keycloak_user_id}/credentials`,
        { headers }
      );

      const otpCred = credRes.data.find((cred) => cred.type === "otp");

      if (otpCred) {
        await axios.delete(
          `${KEYCLOAK_BASE_ADMIN_URL}/users/${keycloak_user_id}/credentials/${otpCred.id}`,
          { headers }
        );
      }

      // 2. Remove CONFIGURE_TOTP from requiredActions
      const userRes = await axios.get(
        `${KEYCLOAK_BASE_ADMIN_URL}/users/${keycloak_user_id}`,
        { headers }
      );

      const updatedActions = (userRes.data.requiredActions || []).filter(
        (action) => action !== "CONFIGURE_TOTP"
      );

      await axios.put(
        `${KEYCLOAK_BASE_ADMIN_URL}/users/${keycloak_user_id}`,
        { requiredActions: updatedActions },
        { headers }
      );

      await usersModel.findOneAndUpdate(
        { keycloak_user_id },
        { isMFAEnabled: false },
        { new: true }
      );

      return handleResponse(
        res,
        true,
        statusCodes.OK,
        "MFA disabled successfully..!"
      );
    }
  } catch (error) {
    console.error("error", error?.response?.data || error.message);
    return handleResponse(
      res,
      false,
      statusCodes.INTERNAL_SERVER_ERROR,
      error?.response?.data?.error || error.message
    );
  }
};
```

**Request**:

- **Headers**:
  - `Authorization`: `Bearer <KEYCLOAK_ACCESS_TOKEN>`
- **Body**:

  ```json
  {
    "keycloak_user_id": "<KEYCLOAK_USER_ID>",
    "status": true
  }
  ```

**Response**:

- **Success** (200 OK):

  ```json
  {
    "success": true,
    "status": 200,
    "message": "MFA enabled Successfully..!" // or "MFA disabled successfully..!"
  }
  ```

- **Error**:
  - 400 Bad Request: "Missing KEYCLOAK_USER_ID, status or BEARER_TOKEN" or "MFA is already enabled/disabled for the user..!"
  - 404 Not Found: "User not found"
  - 500 Internal Server Error: "&lt;ERROR_MESSAGE&gt;"

**Logic**:

- Validates required fields and bearer token.
- For enabling MFA:
  - Checks if MFA is already enabled.
  - Updates Keycloak user with `CONFIGURE_TOTP` in `requiredActions`.
  - Sets `isMFAEnabled` to `true` in the database.
- For disabling MFA:
  - Checks if MFA is already disabled.
  - Removes OTP credentials and `CONFIGURE_TOTP` from `requiredActions` in Keycloak.
  - Sets `isMFAEnabled` to `false` in the database.

### 3. Reset MFA (`auth.controller.js`)

**Endpoint**: `POST /auth/reset-mfa`

**Description**: Resets MFA for a tenant user by deleting existing OTP credentials and triggering re-enrollment.

**Code**:

```javascript
const resetMFAKeycloak = async (req, res) => {
  try {
    const { keycloak_user_id } = req.body;
    const bearerToken = req.headers.authorization?.split(" ")[1];

    const validateRequiredFields = validateFields(
      { keycloak_user_id, bearerToken },
      res
    );
    if (!validateRequiredFields) return;

    // Step 1: Get user
    const userRes = await axios.get(
      `${KEYCLOAK_BASE_ADMIN_URL}/users/${keycloak_user_id}`,
      {
        headers: {
          Authorization: `Bearer ${bearerToken}`,
        },
      }
    );
    const user = userRes.data;

    // Step 2: Delete OTP credentials
    const credRes = await axios.get(
      `${KEYCLOAK_BASE_ADMIN_URL}/users/${keycloak_user_id}/credentials`,
      {
        headers: {
          Authorization: `Bearer ${bearerToken}`,
        },
      }
    );

    const otpCreds = credRes.data.filter((cred) => cred.type === "otp");

    for (const otp of otpCreds) {
      await axios.delete(
        `${KEYCLOAK_BASE_ADMIN_URL}/users/${keycloak_user_id}/credentials/${otp.id}`,
        {
          headers: {
            Authorization: `Bearer ${bearerToken}`,
          },
        }
      );
    }

    // Step 3: Add CONFIGURE_TOTP to requiredActions if not already present
    const updatedActions = Array.from(
      new Set([...(user.requiredActions || []), "CONFIGURE_TOTP"])
    );

    await axios.put(
      `${KEYCLOAK_BASE_ADMIN_URL}/users/${keycloak_user_id}`,
      {
        ...user,
        requiredActions: updatedActions,
      },
      {
        headers: {
          Authorization: `Bearer ${bearerToken}`,
        },
      }
    );

    return handleResponse(
      res,
      true,
      statusCodes.OK,
      "MFA reset: OTP credential deleted and re-enrollment triggered"
    );
  } catch (error) {
    return handleResponse(
      res,
      false,
      statusCodes.INTERNAL_SERVER_ERROR,
      error.response?.data?.error || error.message
    );
  }
};
```

**Request**:

- **Headers**:
  - `Authorization`: `Bearer <KEYCLOAK_ACCESS_TOKEN>`
- **Body**:

  ```json
  {
    "keycloak_user_id": "<KEYCLOAK_USER_ID>"
  }
  ```

**Response**:

- **Success** (200 OK):

  ```json
  {
    "success": true,
    "status": 200,
    "message": "MFA reset: OTP credential deleted and re-enrollment triggered"
  }
  ```

- **Error**:
  - 400 Bad Request: Missing required fields
  - 500 Internal Server Error: "&lt;ERROR_MESSAGE&gt;"

**Logic**:

- Validates required fields and bearer token.
- Fetches user details from Keycloak.
- Deletes all OTP credentials.
- Adds `CONFIGURE_TOTP` to `requiredActions` to trigger MFA re-enrollment.

### 4. Get Keycloak Client ID by Email or Username (`user.controller.js`)

**Endpoint**: `POST /users/get-keycloak-client-id`

**Description**: Retrieves the Keycloak client ID for a user based on their email or username.

**Code**:

```javascript
const getKeycloakClientIdByEmailOrUsername = async (req, res) => {
  try {
    const { identifier } = req.body;

    // Validate required fields
    const validationError = validateFields({ identifier }, res);
    if (validationError) return;

    const user = await usersModel.findOne({
      $or: [{ email: identifier }, { username: identifier }],
    });
    if (!user) {
      return handleResponse(
        res,
        false,
        statusCodes.NOT_FOUND,
        "User not found..!"
      );
    }

    return handleResponse(
      res,
      true,
      statusCodes.OK,
      "Keycloak client_id fetched successfully..!",
      user.keycloak_client_id
    );
  } catch (error) {
    return handleResponse(
      res,
      false,
      statusCodes.INTERNAL_SERVER_ERROR,
      error.message
    );
  }
};
```

**Request**:

- **Headers**:
  - `Authorization`: `Bearer <KEYCLOAK_ACCESS_TOKEN>`
- **Body**:

  ```json
  {
    "identifier": "<EMAIL_OR_USERNAME>"
  }
  ```

**Response**:

- **Success** (200 OK):

  ```json
  {
    "success": true,
    "status": 200,
    "message": "Keycloak client_id fetched successfully..!",
    "data": "<KEYCLOAK_CLIENT_ID>"
  }
  ```

- **Error**:
  - 400 Bad Request: Missing `IDENTIFIER`
  - 404 Not Found: "User not found..!"
  - 500 Internal Server Error: "&lt;ERROR_MESSAGE&gt;"

**Logic**:

- Validates the `IDENTIFIER` field.
- Queries the `usersModel` for a user matching the `EMAIL` or `USERNAME`.
- Returns the `KEYCLOAK_CLIENT_ID` if found.

### 5. Add New Client (`client.controller.js`)

**Endpoint**: `POST /clients/add-client`

**Description**: Creates a new client with associated user, role, and module permissions. Supports file uploads for company logo, favicon, and user profile image.

**Code**:

```javascript
const addNewClient = async (req, res) => {
  try {
    const {
      // client related fields
      company_name,
      email,
      phoneNo,
      address,
      city,
      state,
      country,
      zipCode,
      createdBy,
      founded_year,
      privacy_policy_link,
      terms_of_service,
      company_website,
      contact_us,
      companyLogoURL,
      company_favicon,
      rootUrl,
      baseUrl,
      redirectUris,
      webOrigins,
      adminUrl,

      // user related fields
      userEmailId,
      phone,
      firstName,
      lastName,
      password,
      role,
      modulePermissions,
      plans,
      department_id,
      isActive,
    } = req.body;
    const files = req.files; // Access files from req.files

    // Validate input fields
    const validationError = validateFields(
      { company_name, email, phoneNo, address, city, state, country, zipCode },
      res
    );
    if (validationError) return;

    // Check for existing client
    const existingClient = await clientModel.findOne({
      company_name: { $regex: new RegExp("^" + company_name + "$", "i") },
      deletedAt: null,
    });
    if (existingClient) {
      return handleResponse(
        res,
        false,
        statusCodes.CONFLICT,
        "Client with this company name already exists..!"
      );
    }

    // Use Keycloak user ID directly as createdBy
    const keycloakUserId = req.user.sub; // Get Keycloak user ID from req.user.sub
    if (!keycloakUserId) {
      return handleResponse(
        res,
        false,
        statusCodes.BAD_REQUEST,
        "No authenticated user found in request"
      );
    }
    const createdByValue = createdBy || keycloakUserId; // Use provided createdBy or fallback to keycloakUserId

    // Parse modulePermissions
    let parsedModulePermissions = [];
    if (modulePermissions) {
      try {
        parsedModulePermissions = JSON.parse(modulePermissions);
      } catch (error) {
        return handleResponse(
          res,
          false,
          statusCodes.BAD_REQUEST,
          "Invalid modulePermissions format"
        );
      }
    }

    // Validate and extract moduleIds
    const moduleIds = parsedModulePermissions
      .filter((mp) => mongoose.Types.ObjectId.isValid(mp.moduleId))
      .map((mp) => new mongoose.Types.ObjectId(mp.moduleId));

    // Verify moduleIds exist in Module_Master
    if (moduleIds.length > 0) {
      const existingModules = await ModuleMaster.find({
        _id: { $in: moduleIds },
      });
      if (existingModules.length !== moduleIds.length) {
        return handleResponse(
          res,
          false,
          statusCodes.BAD_REQUEST,
          "One or more module IDs are invalid or do not exist"
        );
      }
    } else if (parsedModulePermissions.length > 0) {
      return handleResponse(
        res,
        false,
        statusCodes.BAD_REQUEST,
        "No valid module IDs provided in modulePermissions"
      );
    }

    // Parse plans
    let parsedPlans = [];
    if (plans) {
      try {
        parsedPlans = JSON.parse(plans);
      } catch (error) {
        return handleResponse(
          res,
          false,
          statusCodes.BAD_REQUEST,
          "Invalid plans format"
        );
      }
    }

    // Validate and process plan details
    let planData = [];
    if (parsedPlans.length > 0) {
      for (const plan of parsedPlans) {
        const {
          plan_id,
          startDate: providedStartDate,
          isActive: planIsActive,
        } = plan;

        // Validate plan_id
        if (!mongoose.Types.ObjectId.isValid(plan_id)) {
          return handleResponse(
            res,
            false,
            statusCodes.BAD_REQUEST,
            `Invalid plan ID format: ${plan_id}`
          );
        }

        // Fetch plan details
        const planDetails = await plansModel.findById(plan_id);
        if (!planDetails) {
          return handleResponse(
            res,
            false,
            statusCodes.BAD_REQUEST,
            `Specified plan does not exist: ${plan_id}`
          );
        }

        // Validate duration
        const durationMonths = parseInt(planDetails.duration, 10);
        if (isNaN(durationMonths) || durationMonths <= 0) {
          return handleResponse(
            res,
            false,
            statusCodes.BAD_REQUEST,
            `Invalid plan duration for plan: ${plan_id}`
          );
        }

        // Set startDate and endDate
        const startDate = providedStartDate
          ? new Date(providedStartDate)
          : new Date();
        if (providedStartDate && isNaN(startDate.getTime())) {
          return handleResponse(
            res,
            false,
            statusCodes.BAD_REQUEST,
            `Invalid startDate for plan: ${plan_id}`
          );
        }

        const endDate = new Date(startDate);
        endDate.setMonth(endDate.getMonth() + durationMonths);

        planData.push({
          plan_id: new mongoose.Types.ObjectId(plan_id),
          startDate,
          endDate,
          isActive: planIsActive !== undefined ? planIsActive : true,
        });
      }
    }

    // Parse redirectUris
    let parsedRedirectUris = redirectUris || [];
    if (typeof redirectUris === "string") {
      try {
        parsedRedirectUris = JSON.parse(redirectUris);
      } catch (error) {
        return handleResponse(
          res,
          false,
          statusCodes.BAD_REQUEST,
          "Invalid redirectUris format"
        );
      }
    }
    if (!Array.isArray(parsedRedirectUris)) {
      return handleResponse(
        res,
        false,
        statusCodes.BAD_REQUEST,
        "redirectUris must be an array"
      );
    }

    // Parse webOrigins
    let parsedWebOrigins = webOrigins || [];
    if (typeof webOrigins === "string") {
      try {
        parsedWebOrigins = JSON.parse(webOrigins);
      } catch (error) {
        return handleResponse(
          res,
          false,
          statusCodes.BAD_REQUEST,
          "Invalid webOrigins format"
        );
      }
    }
    if (!Array.isArray(parsedWebOrigins)) {
      return handleResponse(
        res,
        false,
        statusCodes.BAD_REQUEST,
        "webOrigins must be an array"
      );
    }

    // MongoDB Operations
    // Create new client with plan details and modules
    const clientId = company_name.toLowerCase(); // e.g., testcorp
    const newClient = new clientModel({
      company_name,
      email,
      phoneNo,
      address,
      city,
      state,
      country,
      zipCode,
      createdBy: createdByValue, // Use Keycloak ID as string
      isActive: isActive !== undefined ? isActive : true,
      platform: "AWS",
      plans: planData,
      modules: moduleIds,
      keycloak_client_id: clientId,
      keycloak_organization: company_name,
      keycloak_redirectUris: JSON.stringify(parsedRedirectUris), // Store as string
      keycloak_webOrigins: JSON.stringify(parsedWebOrigins), // Store as string
      companyLogoURL,
      companyLogoPublicId,
      company_favicon,
      company_favicon_public_id,
      company_website,
      contact_us,
      founded_year,
      privacy_policy_link,
      terms_of_service,
      department_id,
      rootUrl,
      baseUrl,
      adminUrl,
      status: "pending", // Set default status as per schema
    });

    // Save client first to get _id
    await newClient.save();

    // Handle company logo upload
    let companyLogoUrl = null;
    let companyLogoPath = null;
    if (files && files.logo && files.logo[0]) {
      const companyFile = files.logo[0];
      const fileExtension = companyFile.originalname.split(".").pop();
      const fileName = `company-logos/${Date.now()}.${fileExtension}`;

      // Pass client _id in request
      const modifiedReq = { ...req, clientId: newClient._id };

      companyLogoUrl = await uploadFileToS3(
        modifiedReq,
        companyFile.buffer,
        fileName,
        companyFile.mimetype
      );
      companyLogoPath = fileName;

      newClient.companyLogoURL = companyLogoUrl;
      newClient.companyLogoPublicId = companyLogoPath;
    }

    // Handle company favicon upload
    let companyFaviconUrl = null;
    let companyFaviconPath = null;
    if (files && files.favicon && files.favicon[0]) {
      const faviconFile = files.favicon[0];
      const fileExtension = faviconFile.originalname.split(".").pop();
      const fileName = `company-favicons/${Date.now()}.${fileExtension}`;

      // Pass client _id in request
      const modifiedReq = { ...req, clientId: newClient._id };

      companyFaviconUrl = await uploadFileToS3(
        modifiedReq,
        faviconFile.buffer,
        fileName,
        faviconFile.mimetype
      );
      companyFaviconPath = fileName;

      newClient.company_favicon = companyFaviconUrl;
      newClient.company_favicon_public_id = companyFaviconPath;
    }

    // Handle user profile image upload
    let userImageUrl = null;
    let userImagePath = null;
    if (files && files.profile_image && files.profile_image[0]) {
      const userFile = files.profile_image[0];
      const fileExtension = userFile.originalname.split(".").pop();
      const fileName = `user-profiles/${Date.now()}.${fileExtension}`;

      // Pass client _id in request
      const modifiedReq = { ...req, clientId: newClient._id };

      userImageUrl = await uploadFileToS3(
        modifiedReq,
        userFile.buffer,
        fileName,
        userFile.mimetype
      );
      userImagePath = fileName;
    }

    // Update client with file URLs
    await newClient.save();

    // Send notification to super admins
    try {
      const superAdmins = await usersModel.find({
        roleName: CONSTANTS.SUPER_ADMIN_ROLE,
        deletedAt: null,
      });
      for (const admin of superAdmins) {
        if (admin.keycloak_user_id) {
          await sendNotification(
            `New client ${company_name} created and pending approval`,
            admin.keycloak_user_id
          );
        }
      }
    } catch (notificationError) {
      console.error(
        "Failed to send notification to super admins:",
        notificationError.message
      );
      // Do not fail the request; log the error and continue
    }

    // Validate and assign role
    if (!role) {
      return handleResponse(
        res,
        false,
        statusCodes.BAD_REQUEST,
        "Role is required"
      );
    }

    const newRole = new rolesModel({
      name: role,
      company_id: newClient._id,
    });

    await newRole.save();

    // Generate QR code for 2FA
    const { AuthSecret } = await generateQRCode({
      appName: process.env.appName || "MyApp",
    });

    // Validate user modules against client modules
    const clientModuleIds = moduleIds.map((id) => id.toString());
    const validUserModuleIds = moduleIds.filter((id) =>
      clientModuleIds.includes(id.toString())
    );

    if (moduleIds.length > 0 && validUserModuleIds.length === 0) {
      return handleResponse(
        res,
        false,
        statusCodes.BAD_REQUEST,
        "No valid modules provided for user or modules not associated with the client"
      );
    }

    // Check if user already exists by email
    let newUser = await usersModel.findOne({ email: userEmailId });
    const hashedPassword = await bcrypt.hash(
      password || "defaultPassword123",
      10
    );

    if (newUser) {
      newUser.firstName = firstName || newUser.firstName;
      newUser.lastName = lastName || newUser.lastName;
      newUser.email = userEmailId || newUser.email;
      newUser.phone = phone || newUser.phone;
      newUser.roleName = role; // Store role name
      newUser.department_id = department_id || newUser.department_id;
      if (password) newUser.password = hashedPassword;
      newUser.client_id = newClient._id; // Store as string
      newUser.modules =
        validUserModuleIds.length > 0 ? validUserModuleIds : newUser.modules;
      if (userImageUrl) newUser.profilePictureURL = userImageUrl;
      if (userImagePath) newUser.profilePicturePublicId = userImagePath;
      newUser.AuthSecret = AuthSecret;
      newUser.username = userEmailId;
    } else {
      newUser = new usersModel({
        firstName: firstName || "Default FirstName",
        lastName: lastName || "Default LastName",
        email: userEmailId || email,
        password: hashedPassword,
        phone: phone || "0000000000",
        role: newRole._id,
        client_id: newClient._id, // Store as string
        modules: validUserModuleIds,
        department_id: department_id || null,
        profilePictureURL: userImageUrl || null,
        profilePicturePublicId: userImagePath || null,
        AuthSecret,
        username: userEmailId,
        roleName: role, // Store role name
        createdBy,
      });
    }

    await newUser.save();

    // Handle module permissions
    if (parsedModulePermissions.length > 0) {
      for (const { moduleId, permissionIds } of parsedModulePermissions) {
        const moduleObjectId = new mongoose.Types.ObjectId(moduleId);
        if (!clientModuleIds.includes(moduleId)) {
          continue;
        }
        const permissionIdsArray = permissionIds
          .filter((id) => mongoose.Types.ObjectId.isValid(id))
          .map((id) => new mongoose.Types.ObjectId(id));

        const module = await ModuleMaster.findById(moduleId);
        if (!module) {
          continue;
        }

        let userPermission = await UserHasModulePermission.findOne({
          moduleId: moduleObjectId,
          user_id: newUser._id,
        });

        if (userPermission) {
          userPermission.permissionIds = permissionIdsArray;
        } else {
          userPermission = new UserHasModulePermission({
            moduleId: moduleObjectId,
            permissionIds: permissionIdsArray,
            user_id: newUser._id,
          });
        }

        await userPermission.save();
      }
    }

    return handleResponse(
      res,
      true,
      statusCodes.CREATED,
      "Request Sent successfully..!",
      {
        client: {
          ...newClient._doc,
          plans: newClient.plans,
          modules: newClient.modules,
          companyLogoURL: newClient.companyLogoURL,
          companyLogoPublicId: newClient.companyLogoPublicId,
          company_favicon: newClient.company_favicon,
          company_favicon_public_id: newClient.company_favicon_public_id,
          company_website: newClient.company_website,
          contact_us: newClient.contact_us,
          founded_year: newClient.founded_year,
          terms_of_service: newClient.terms_of_service,
          privacy_policy_link: newClient.privacy_policy_link,
          keycloak_client_id: newClient.keycloak_client_id,
          keycloak_organization: newClient.keycloak_organization,
          keycloak_redirectUris: newClient.keycloak_redirectUris,
          keycloak_webOrigins: newClient.keycloak_webOrigins,
          department_id: newClient.department_id,
          status: newClient.status,
        },
        user: {
          _id: newUser._id,
          email: newUser.email,
          firstName: newUser.firstName,
          lastName: newUser.lastName,
          phone: newUser.phone,
          role: newRole._id,
          department_id: newUser.department_id,
          modules: newUser.modules,
          imageUrl: newUser.profilePictureURL,
          AuthSecret: newUser.AuthSecret,
          roleName: newUser.roleName,
        },
      }
    );
  } catch (error) {
    return handleResponse(
      res,
      false,
      statusCodes.INTERNAL_SERVER_ERROR,
      error.message
    );
  }
};
```

**Request**:

- **Headers**:
  - `Authorization`: `Bearer <KEYCLOAK_ACCESS_TOKEN>`
  - `Content-Type`: `multipart/form-data`
- **Body** (Form Data):

  ```json
  {
    "company_name": "<COMPANY_NAME>",
    "email": "<COMPANY_EMAIL>",
    "phoneNo": "<PHONE_NUMBER>",
    "address": "<ADDRESS>",
    "city": "<CITY>",
    "state": "<STATE>",
    "country": "<COUNTRY>",
    "zipCode": "<ZIP_CODE>",
    "createdBy": "<KEYCLOAK_USER_ID>", // Optional, defaults to req.user.sub
    "userEmailId": "<USER_EMAIL>",
    "phone": "<USER_PHONE>",
    "firstName": "<FIRST_NAME>",
    "lastName": "<LAST_NAME>",
    "password": "<PASSWORD>",
    "role": "<ROLE_NAME>",
    "modulePermissions": "[{\"moduleId\": \"<MODULE_ID>\", \"permissionIds\": [\"<PERM_ID1>\", \"<PERM_ID2>\"]}]",
    "plans": "[{\"plan_id\": \"<PLAN_ID>\", \"startDate\": \"<DATE>\", \"isActive\": true}]",
    "founded_year": "<YEAR>",
    "privacy_policy_link": "<URL>",
    "terms_of_service": "<URL>",
    "isActive": true,
    "company_website": "<URL>",
    "contact_us": "<URL>",
    "department_id": "<DEPARTMENT_ID>",
    "rootUrl": "<URL>",
    "baseUrl": "<URL>",
    "redirectUris": "[\"<URL1>\", \"<URL2>\"]",
    "webOrigins": "[\"<URL1>\", \"<URL2>\"]",
    "adminUrl": "<URL>",
    "AWS_S3_BUCKET_NAME": "<BUCKET_NAME>",
    "logo": "<FILE>", // Company logo file
    "favicon": "<FILE>", // Company favicon file
    "profile_image": "<FILE>" // User profile image file
  }
  ```

**Response**:

- **Success** (201 Created):

  ```json
  {
    "success": true,
    "status": 201,
    "message": "Request Sent successfully..!",
    "data": {
      "client": {
        "_id": "<CLIENT_ID>",
        "company_name": "<COMPANY_NAME>",
        "email": "<COMPANY_EMAIL>",
        "phoneNo": "<PHONE_NUMBER>",
        "address": "<ADDRESS>",
        "city": "<CITY>",
        "state": "<STATE>",
        "country": "<COUNTRY>",
        "zipCode": "<ZIP_CODE>",
        "createdBy": "<KEYCLOAK_USER_ID>",
        "isActive": true,
        "platform": "AWS",
        "plans": [
          {
            "plan_id": "<PLAN_ID>",
            "startDate": "<DATE>",
            "endDate": "<DATE>",
            "isActive": true
          }
        ],
        "modules": ["<MODULE_ID>"],
        "keycloak_client_id": "<CLIENT_ID>",
        "keycloak_organization": "<COMPANY_NAME>",
        "keycloak_redirectUris": "[\"<URL1>\", \"<URL2>\"]",
        "keycloak_webOrigins": "[\"<URL1>\", \"<URL2>\"]",
        "companyLogoURL": "<URL>",
        "companyLogoPublicId": "<PATH>",
        "company_favicon": "<URL>",
        "company_favicon_public_id": "<PATH>",
        "company_website": "<URL>",
        "contact_us": "<URL>",
        "founded_year": "<YEAR>",
        "terms_of_service": "<URL>",
        "privacy_policy_link": "<URL>",
        "department_id": "<DEPARTMENT_ID>",
        "status": "pending"
      },
      "user": {
        "_id": "<USER_ID>",
        "email": "<USER_EMAIL>",
        "firstName": "<FIRST_NAME>",
        "lastName": "<LAST_NAME>",
        "phone": "<PHONE>",
        "role": "<ROLE_ID>",
        "department_id": "<DEPARTMENT_ID>",
        "modules": ["<MODULE_ID>"],
        "imageUrl": "<PROFILE_PICTURE_URL>",
        "AuthSecret": "<SECRET>",
        "roleName": "<ROLE_NAME>"
      }
    }
  }
  ```

- **Error**:
  - 400 Bad Request: Missing required fields, invalid formats (e.g., `modulePermissions`, `plans`, `redirectUris`, `webOrigins`), invalid module/plan IDs, or invalid dates
  - 409 Conflict: "Client with this company name already exists..!"
  - 500 Internal Server Error: "&lt;ERROR_MESSAGE&gt;"

**Logic**:

- Validates required fields and checks for existing clients.
- Uses `req.user.sub` as `createdBy` if not provided.
- Parses and validates `modulePermissions`, `plans`, `redirectUris`, and `webOrigins`.
- Uploads company logo, favicon, and user profile image to AWS S3 if provided.
- Creates a new client with associated plans and modules.
- Creates or updates a user with the specified role and modules.
- Assigns module permissions to the user.
- Sends notifications to super admins for approval.
- Generates a TOTP secret for the user.

## Middleware

### `isAuthenticated` (`auth.middleware.js`)

**Description**: Verifies the Keycloak access token using the `jwks-rsa` library.

**Code**:

```javascript
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const { handleResponse } = require("../utils/response_handler.js");
const statusCodes = require("../utils/status_codes.js");

// Replace with your Keycloak domain and realm
const keycloakIssuer = process.env.KEYCLOAK_ISSUER;

const client = jwksClient({
  jwksUri: `${keycloakIssuer}/protocol/openid-connect/certs`,
});

// Helper function to get signing key
const getKey = (header, callback) => {
  client.getSigningKey(header.kid, function (err, key) {
    if (err) {
      return callback(err);
    }
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
};

// #region isAuthenticated
const isAuthenticated = (req, res, next) => {
  try {
    const accessToken =
      req.headers.authorization && req.headers.authorization.split(" ")[1];

    if (!accessToken) {
      return handleResponse(
        res,
        false,
        statusCodes.UNAUTHORIZED,
        "Unauthorized! Login Again..!"
      );
    }

    jwt.verify(
      accessToken,
      getKey,
      {
        algorithms: ["RS256"],
        issuer: keycloakIssuer, // Optional: Ensures token came from your realm
      },
      (err, decoded) => {
        if (err) {
          return handleResponse(
            res,
            false,
            statusCodes.UNAUTHORIZED,
            "Unauthorized! Invalid Token!"
          );
        }

        req.user = decoded;
        next();
      }
    );
  } catch (error) {
    return handleResponse(
      res,
      false,
      statusCodes.UNAUTHORIZED,
      "Unauthorized! Invalid Token!"
    );
  }
};

module.exports = isAuthenticated;
```

**Logic**:

- Extracts the access token from the `Authorization` header.
- Verifies the token using the public key from Keycloak's JWKS endpoint.
- Attaches the decoded token to `req.user` if valid.
- Returns 401 Unauthorized for invalid or missing tokens.

**Dependencies**:

- `jwks-rsa`: Fetches and caches the public key for token verification.

## Data Models

### `Users` (`users.model.js`)

**Schema**:

```javascript
const mongoose = require("mongoose");

const UsersSchema = new mongoose.Schema(
  {
    firstName: {
      type: String,
      minLength: [2, "FirstName must be at least 2 characters"],
      maxLength: [50, "FirstName must be less than 50 characters"],
      required: true,
    },
    lastName: {
      type: String,
      minLength: [2, "LastName must be at least 2 characters"],
      maxLength: [50, "LastName must be less than 50 characters"],
      required: true,
    },
    email: {
      type: String,
      required: false,
      unique: true,
    },
    password: {
      type: String,
      required: false,
    },
    phone: {
      type: String,
      required: false,
    },
    role: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Roles",
    },
    roleName: {
      type: String,
    },
    client_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Clients",
    },
    department_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Departments",
    },
    modules: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Module_Master",
      },
    ],
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Users",
    },
    platform: {
      type: String,
      default: "AWS",
    },
    profilePictureURL: {
      type: String,
      default: null,
    },
    profilePicturePublicId: {
      type: String,
      default: null,
    },
    isMFAEnabled: {
      type: Boolean,
      default: true,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    AuthSecret: {
      type: String,
      default: "",
    },
    resetOTP: {
      type: String,
      default: "",
    },
    resetOTPExpireAt: {
      type: Number,
      default: 0,
    },
    ipAddress: {
      type: String,
      default: "",
    },
    isLoggedIn: {
      type: Boolean,
      default: false,
    },
    deletedAt: {
      type: Date,
      default: null,
    },

    // Keycloak Related Fields

    keycloak_user_id: {
      type: String,
      required: false,
    },
    username: {
      type: String,
      required: false,
    },
    realm_roles: {
      type: [String],
      default: [],
      required: false,
    },
    keycloak_client_id: {
      type: String,
      required: false,
    },
    client_roles: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
      required: false,
    },
    session_id: {
      type: String,
      required: false,
    },
    last_login_at: {
      type: Date,
      required: false,
    },
  },
  {
    timestamps: true,
    collection: "Users",
  }
);

const usersModel = mongoose.model("Users", UsersSchema);

module.exports = usersModel;
```

**Description**:

- Stores user information, including Keycloak-specific fields (`KEYCLOAK_USER_ID`, `KEYCLOAK_CLIENT_ID`, `client_roles`, `session_id`).
- Supports MFA with `isMFAEnabled` and `AuthSecret` for TOTP.
- References roles, clients, departments, and modules.

### `Clients` (`client.model.js`)

**Schema**:

```javascript
const mongoose = require("mongoose");

const ClientSchema = new mongoose.Schema(
  {
    company_name: {
      type: String,
      required: true,
    },
    companyLogoURL: {
      type: String,
    },
    companyLogoPublicId: {
      type: String,
    },
    company_favicon: {
      type: String,
    },
    company_favicon_public_id: {
      type: String,
    },
    email: {
      type: String,
      required: false,
    },
    phoneNo: {
      type: String,
      required: false,
    },
    company_website: {
      type: String,
    },
    contact_us: {
      type: String,
    },
    founded_year: {
      type: String,
    },
    terms_of_service: {
      type: String,
    },
    privacy_policy_link: {
      type: String,
    },
    address: {
      type: String,
      required: false,
    },
    city: {
      type: String,
      required: false,
    },
    state: {
      type: String,
      required: false,
    },
    country: {
      type: String,
      required: false,
    },
    zipCode: {
      type: String,
      required: false,
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Users",
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    platform: {
      type: String,
    },
    isTrustCenterEnabled: {
      type: Boolean,
      default: true,
    },
    modules: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Module_Master",
      },
    ],
    plans: [
      {
        plan_id: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Subscription_Plans",
          required: false,
        },
        startDate: {
          type: Date,
          required: false,
        },
        endDate: {
          type: Date,
          required: false,
        },
        isActive: {
          type: Boolean,
          default: null,
        },
      },
    ],
    AWS_S3_ACCESS_KEY_ID: {
      type: String,
    },
    AWS_S3_ACCESS_SECRET_KEY: {
      type: String,
    },
    AWS_REGION: {
      type: String,
    },
    AWS_S3_BUCKET_NAME: {
      type: String,
    },
    DROPBOX_APP_KEY: {
      type: String,
    },
    DROPBOX_APP_SECRET: {
      type: String,
    },
    DROPBOX_REFRESH_TOKEN: {
      type: String,
    },
    deletedAt: {
      type: Date,
      default: null,
    },
    tc_theme: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Trust_Center_Themes",
      default: null,
    },
    tc_powered_by: {
      type: String,
      default: null,
    },
    tc_is_search_allowed: {
      type: Boolean,
      default: false,
    },
    tc_is_updates_allowed: {
      type: Boolean,
      default: false,
    },
    tc_is_faqs_allowed: {
      type: Boolean,
      default: false,
    },
    tc_is_request_doc_allowed: {
      type: Boolean,
      default: false,
    },
    tc_is_request_spc_allowed: {
      type: Boolean,
      default: false,
    },
    tc_is_ask_your_question_allowed: {
      type: Boolean,
      default: false,
    },
    tc_is_subscribe_allowed: {
      type: Boolean,
      default: false,
    },
    integration_add_ons: {
      type: Number,
      default: 0,
    },
    used_integration_add_ons: {
      type: Number,
      default: 0,
    },
    status: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
    },

    // Keycloak Related Fields

    keycloak_client_id: {
      type: String,
    },
    keycloak_created_by: {
      type: String,
    },
    keycloak_organization: {
      type: String,
    },
    keycloak_redirectUris: {
      type: String,
    },
    keycloak_webOrigins: {
      type: String,
    },
  },
  {
    timestamps: true,
    collection: "Clients",
  }
);

// Add index on plans.endDate for efficient expiration checks
ClientSchema.index({ "plans.endDate": 1 });

const Client = mongoose.model("Clients", ClientSchema);

module.exports = Client;
```

**Description**:

- Stores client information, including Keycloak-specific fields (`KEYCLOAK_CLIENT_ID`, `keycloak_organization`, `keycloak_redirectUris`, `keycloak_webOrigins`).
- Supports file uploads for logos and favicons.
- Includes trust center settings and integration add-ons.

### `Role_Has_Permission` (`role_has_permission.model.js`)

**Schema**:

```javascript
const mongoose = require("mongoose");

const roleHasPermissionSchema = new mongoose.Schema(
  {
    roleId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Roles",
      required: true,
    },
    role: {
      type: String,
      required: true,
    },
    permissionId: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Permissions",
        required: true,
      },
    ],
  },
  {
    strictPopulate: false,
    timestamps: true,
    collection: "Role_Has_Permission",
  }
);

const roleHasPermissionModel = mongoose.model(
  "Role_Has_Permission",
  roleHasPermissionSchema
);

module.exports = roleHasPermissionModel;
```

**Description**:

- Maps roles to permissions.
- Supports multiple permissions per role.

## Dependencies

- **Node.js Packages**:
  - `jsonwebtoken`: For decoding and verifying JWTs.
  - `jwks-rsa`: For fetching Keycloak's public keys to verify tokens.
  - `mongoose`: For MongoDB object modeling.
  - `axios`: For making HTTP requests to Keycloak.
  - `bcrypt`: For hashing user passwords.

## Environment Variables

- `KEYCLOAK_ISSUER`: Keycloak realm issuer URL (e.g., `<KEYCLOAK_BASE_URL>/realms/:REALM_NAME`).

## Notes

- All APIs require a valid Keycloak access token in the `Authorization` header.
