package authz

default allow = false
RUD = ["GET", "PATCH", "DELETE"]
BLOCKED_USERS = [2,3]

allow {
    has_role
}

has_role{
    input.method == "POST"
    input.path == ["api", "v1", "users"]
}

has_role{
    some i,j, user_id
    input.method == RUD[i]
    input.path = ["api","v1","users", user_id]
    user_id != BLOCKED_USERS[j]
}