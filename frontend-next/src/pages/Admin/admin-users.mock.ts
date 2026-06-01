import type { AdminUser } from './admin.types'

export const MOCK_USERS: AdminUser[] = [
  { id: 'u1', username: 'admin',   email: 'admin@maison.local',   role: 'admin',  status: 'active',   emailVerified: true,  createdAt: '2025-01-01', lastLogin: '29/05/2026 10:05' },
  { id: 'u2', username: 'leang',   email: 'leang@maison.local',   role: 'user',   status: 'active',   emailVerified: true,  createdAt: '2025-02-14', lastLogin: '28/05/2026 22:30' },
  { id: 'u3', username: 'marie',   email: 'marie@maison.local',   role: 'user',   status: 'active',   emailVerified: true,  createdAt: '2025-06-10', lastLogin: '27/05/2026 09:00' },
  { id: 'u4', username: 'guest',   email: 'guest@maison.local',   role: 'viewer', status: 'disabled', emailVerified: false, createdAt: '2025-09-01', lastLogin: null },
  { id: 'u5', username: 'invite1', email: 'new1@maison.local',    role: 'user',   status: 'pending',  emailVerified: false, createdAt: '2026-05-28', lastLogin: null },
  { id: 'u6', username: 'invite2', email: 'new2@maison.local',    role: 'user',   status: 'pending',  emailVerified: false, createdAt: '2026-05-29', lastLogin: null },
]
