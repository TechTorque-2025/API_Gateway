# 🌐 API Gateway

This service is the single entry point for all client requests in the TechTorque 2025 system. It is responsible for routing, authentication, rate limiting, and enriching requests.

### 🎯 Key Responsibilities

-   **Request Routing:** Maps incoming URL paths (e.g., `/api/v1/vehicles`) to the correct internal microservice (e.g., `vehicle-service`).
-   **Authentication:** Validates JWTs for all protected endpoints.
-   **Header Enrichment:** Injects `X-User-Subject` and `X-User-Roles` headers into requests after successful authentication.
-   **CORS:** Manages all Cross-Origin Resource Sharing policies for the frontend application.

### ⚙️ Tech Stack

-   **Language:** Go
-   **Router:** `chi/v5`
-   **JWT Library:** `golang-jwt/jwt/v5`

### 🚀 Running Locally

This service is designed to be run as part of the main `docker-compose` setup from the project's root directory.

```bash
# From the root of the TechTorque-2025 project
docker-compose up --build api-gateway