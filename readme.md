# Customer & Invoice Management System | Spring Boot & Angular

A **full stack application** built with **Spring Boot (backend)** and **Angular (frontend)**, designed for comprehensive customer relationship management and automated invoicing.

The project implements a high-security architecture featuring **MFA via Twilio**, professional reporting with **JasperReports**, and a fully containerized environment using **Docker**.

---

## 🚀 Key Highlights

- 🔐 **Advanced Security**: Secure authentication via **JWT** with **Role-Based Access Control (RBAC)**, Angular Guards, and Interceptors.
- 📱 **Multi-Factor Authentication (MFA)**: Enhanced login security using **Twilio SMS** integration.
- 📄 **Reporting**: Exports in **PDF, Excel, and CSV** formats powered by **JasperReports**.
- 📧 **Automated Workflows**: Email services for **Account Activation** and **Password Reset**.
- 🗺️ **Geospatial Data**: Interactive **Leaflet Map** visualization showing customer distribution by region.
- ⚙️ **Full CRUD & Performance**: Optimized management of Customers and Invoices with **pagination, search, and caching**.
- 🛡️ **System Auditing**: Event logging system with the capability to report and track system activities.
- 🐳 **DevOps Ready**: **Dockerized** application for seamless deployment and scalability.
- 🧱 **API Documentation**: Interactive documentation provided by **Swagger/OpenAPI**.

---

## 🛠 Tech Stack

| Component | Technologies |
|---|---|
| **Backend** | Java, Spring Boot, Spring Security, JPA, Hibernate, MySQL/PostgreSQL |
| **Frontend** | Angular, TypeScript, Bootstrap, Leaflet.js, CSS Animations |
| **Security** | JWT, Twilio SMS API, Bcrypt |
| **Reporting** | JasperReports (PDF, XLSX, CSV) |
| **DevOps** | Docker, Docker Compose |
| **Tools** | Swagger, Maven, Git |

---

## 📦 Features in Detail

### User & Profile Management
The system includes a robust user profile section where users can manage account settings, view assigned roles/permissions, and track their activity logs.

### Responsive UI/UX
Designed with a "Mobile First" approach using **Bootstrap**, ensuring a modern, clean, and attractive interface with smooth animations for a premium user experience.

### Reporting & Analytics
Beyond standard CRUD, the application allows administrators to generate complex business reports and visualize customer locations on an interactive map.

---
## 🎥 Application Demo Video

**📺 Watch here:** https://www.youtube.com/watch?v=Kh9sh8FGMsI

---
## 📐 ER Diagram & Architecture

### 🗄️ Database Schema (ER Diagram)
![ER Diagram](./img/ER.png)

### 🏗️ System Architecture
![Architecture](./img/architecture_1.png)

---

## 📘 Documentation

### 🔹 Backend / Swagger ui endpoints

 - The Swagger REST API documentation is available throw the endpoint /swagger-ui/index.html
 
  ![Open API Docs](./img/OpenAPiDoc.png)
  
---

## 🛠️ Features

### 🔐 Security & Access Control
* **Dual-Factor Authentication (2FA)**: High-security login flow integrating **Twilio SMS API** for identity verification.
* **JWT Security Architecture**: Stateless authentication using JSON Web Tokens with custom **Interceptors** for automatic token injection in HTTP headers.
* **Route Protection**: Advanced **Angular Guards** (CanActivate) to prevent unauthorized access based on user roles and permissions.
- **Account Self-Service**: Automated email triggers for **Account Activation** and secure **Password Reset** via Spring Mail.

### 📊 Business Intelligence & Reporting
* **Multi-Format Exports**: Enterprise-grade reporting system using **JasperReports** to generate professional **PDF, Excel, and CSV** documents.
* **Geospatial Insights**: Interactive **Leaflet.js** map integration to visualize customer distribution by region, supporting both **UTM and Geographic** coordinate systems.
* **Audit Logging**: Comprehensive event tracking system that records user actions and system events for security auditing.

### 💼 Customer & Invoice Management
* **Advanced Data Handling**: Full CRUD operations for Customers and Invoices with complex relational mapping (One-to-Many).
* **Smart Tables**: High-performance UI components featuring **server-side pagination**, real-time **search filters**, and sorting.
* **Data Consistency**: Backend validation using **Hibernate Validator** and frontend reactive form validation.

### ⚡ Performance & UX
* **Caching Layer**: Implementation of Spring Cache to reduce database load and improve response times for frequent queries.
* **Responsive UI**: A "Mobile-First" interface built with **Bootstrap** and enhanced with **CSS3 animations** for a modern look and feel.
* **API Excellence**: Fully documented REST API using **Swagger (OpenAPI 3)**, making it easy to test and integrate.

### 🐳 DevOps & Deployment
* **Containerization**: Ready-to-use **Docker & Docker Compose** configuration for both backend and frontend environments.
* **Environment Agnostic**: Easy configuration via environment variables for quick deployment across different servers.

---

## ⚙️ Technologies

### 🖥️ Backend (Spring Boot 3.4.10)
- **Java 17**: Leveraging modern language features.
- **Spring Security**: Advanced authentication flow and role-based access control.
- **Spring Data JPA & JDBC**: Persistent data layer with MySQL integration.
- **JWT (auth0)**: Secure token-based authentication.
- **Twilio SDK**: Integration for SMS-based Multi-Factor Authentication (MFA).
- **JasperReports**: Enterprise-level reporting (PDF, CSV, and Excel .xlsx).
- **Spring Mail**: Automated email triggers for account lifecycle management.
- **YAUAA (Yet Another UserAgent Analyzer)**: Parsing user agent data for detailed event logging and security auditing.
- **Lombok**: Reducing boilerplate code for cleaner entity and DTO models.
- **SpringDoc OpenAPI (Swagger UI)**: Interactive REST API documentation.

### 🎨 Frontend (Angular 16)
- **TypeScript**: Type-safe frontend development.
- **RxJS**: Reactive programming for asynchronous data streams and state management.
- **Angular JWT**: Client-side handling and decoding of authentication tokens.
- **Leaflet.js**: Interactive maps for geospatial visualization of customers.
- **Bootstrap & Icons**: Responsive layout and modern UI components.
- **SweetAlert2 & Angular Notifier**: Enhanced user feedback and toast notifications.
- **Particles.js**: Professional visual effects for an attractive landing experience.

### 🧪 DevOps
- **Docker & Docker Compose**: Multi-container orchestration for seamless deployment.
- **Maven**: Dependency management and build automation with profile support (Dev/Prod).

---

## Interfaces 🖥️

### 🔐 Authentication
- **Login**  
  ![login](img/01login.png)

- **Register**  
  ![register](img/02register.png)
  
- **Password reset**  
  ![Password reset](img/03passwordreset.png)
  
- **Password verification**  
  ![Password reset](img/04passwordVerif.png)
  
- **Account verification**  
  ![Password reset](img/05accountVerif.png)

### 🏠 Home
  ![home](img/06home.png)

### 👥 Customer
- **Customer list**  
  ![customers](img/08AllCustomers.png)

- **New customer**  
  ![New customer](img/07newCustomer.png)

- **Customer detail**  
  ![Customer detail](img/08CustomerDetails.png)

- **Customer invoice**  
  ![Customer invoice](img/08CustomerInvoice.png)

### 💳 Invoices
- **Invoices List**  
  ![Invoices](img/10AllInvoices.png)

- **New invoice**  
  ![New invoice](img/09NewInvoice.png)

### 👤 Profile
- **Profile view**  
  ![Profile](img/11Profile.png)

- **Profile password tab**  
  ![Profile password](img/12ProfilePassword.png)
  
- **Profile roles tab**  
  ![Profile roles](img/13ProfileRoles.png)
  
- **Profile settings tab**  
  ![Profile settings](img/14ProfileSettings.png)
  
- **Profile auth tab**  
  ![Profile auth](img/15ProfileAuth.png)
  
- **Profile event report**  
  ![Profile events](img/16ProfileEventReport.png)
  
- **Profile event report detail**  
  ![Profile event detail](img/17ProfileEventReportDetail.png)
  
### 🔔 Notifications
- **SMS**  
  ![SMS notifications](img/notifi_sms.png)

- **EMAILS**  
  ![Email notifications](img/notif_email.png)
  
