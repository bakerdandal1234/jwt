### Project Title: **Advanced Blog API with JWT Authentication**

### **Project Overview**
This project is a robust, secure, and scalable RESTful API for a blog platform, built on the Laravel framework. It features a complete user authentication system using JSON Web Tokens (JWT) with refresh token capabilities, role-based access control (RBAC), and social media integration. The application provides full CRUD (Create, Read, Update, Delete) functionality for core blogging features like posts, categories, and comments.

### **Key Technologies**
*   **Backend:** PHP, Laravel
*   **API:** RESTful
*   **Authentication:** JWT (JSON Web Tokens) with a refresh token system for persistent and secure sessions.
*   **Authorization:** Role-based access control (RBAC) to manage user permissions (e.g., admin, editor, user).
*   **Social Login:** Integration for authentication via social media platforms.
*   **Database:** SQL-based, managed through Laravel's Eloquent ORM and migrations.
*   **Frontend Tooling:** Vite for asset bundling, with Tailwind CSS for styling.
*   **Testing:** PHPUnit for unit and feature testing.

### **Core Features**
*   **Secure User Authentication:**
    *   User registration with email verification.
    *   Stateless API authentication using JWT.
    *   Secure password reset functionality.
    *   Login via social media accounts.
*   **Role & Permission Management:**
    *   Defines user roles (e.g., Admin, User) with specific permissions.
    *   Middleware protects routes and actions based on a user's role and permissions.
*   **Content Management:**
    *   **Posts:** Full CRUD operations for creating, reading, updating, and deleting blog posts.
    *   **Categories:** Assign posts to different categories, with full CRUD for category management.
    *   **Comments:** Users can add comments to posts, with management capabilities.
*   **API Endpoints:**
    *   A full suite of API routes for interacting with users, posts, categories, and comments.

This project demonstrates a strong understanding of modern backend development practices, API security, and database management within the Laravel ecosystem.