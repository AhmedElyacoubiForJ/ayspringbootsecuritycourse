package edu.yacoubi.ayspringbootsecuritycourse.security;

import static edu.yacoubi.ayspringbootsecuritycourse.security.ApplicationUserPermission.*;
import com.google.common.collect.Sets;
import java.util.Set;

public enum ApplicationUserRole {
    STUDENT(Sets.newHashSet()), // empty
    ADMIN(Sets.newHashSet(
            COURSE_READ,
            COURSE_WRITE,
            STUDENT_READ,
            STUDENT_WRITE)
    );

    private final Set<ApplicationUserPermission> permission;

    ApplicationUserRole(Set<ApplicationUserPermission> permission) {
        this.permission = permission;
    }

    public Set<ApplicationUserPermission> getPermission() {
        return permission;
    }
}
