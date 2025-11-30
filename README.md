# Assignment #9: Company Project Management API

A RESTful API for managing company projects and tasks with role-based access control.

## Setup Instructions

1. Clone the repository
2. Install dependencies: `npm install`
3. Set up environment variables in `.env`
4. Setup the database: `npm run setup`
5. Seed the database: `npm run seed`
6. Start the server: `npm start`

## Current Status

This API is **partially implemented** and needs JWT authentication and role-based authorization added.

### What's Working:
- User registration and login (session-based)
- Full CRUD operations for projects and tasks
- Database relationships and seeding
- Basic authentication middleware

### What You Need to Implement:
- [ ] Add role field to User model
- [ ] Replace session authentication with JWT tokens
- [ ] Create role-based middleware functions
- [ ] Protect endpoints with appropriate role restrictions
- [ ] Test authorization flows

## API Endpoints

### Authentication
- `POST /api/register` - Register new user
- `POST /api/login` - User login
- `POST /api/logout` - User logout

### Users
- `GET /api/users/profile` - Get current user profile
- `GET /api/users` - Get all users

### Projects
- `GET /api/projects` - List projects
- `GET /api/projects/:id` - Get single project
- `POST /api/projects` - Create project
- `PUT /api/projects/:id` - Update project
- `DELETE /api/projects/:id` - Delete project

### Tasks
- `GET /api/projects/:id/tasks` - List tasks for project
- `POST /api/projects/:id/tasks` - Create task
- `PUT /api/tasks/:id` - Update task
- `DELETE /api/tasks/:id` - Delete task

## Sample Users
- `john@company.com` (Employee) - password: password123
- `sarah@company.com` (Manager) - password: password123
- `mike@company.com` (Admin) - password: password123

## Role Permissions (To Be Implemented)
- **Employee**: View projects/tasks, update task status
- **Manager**: Create/edit projects, assign tasks, view team progress
- **Admin**: Full system access, manage users, delete projects
