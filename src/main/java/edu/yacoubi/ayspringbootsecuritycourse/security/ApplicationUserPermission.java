package edu.yacoubi.ayspringbootsecuritycourse.security;

public enum ApplicationUserPermission {
    STUDENT_READ("student:read"),
    STUDENT_WRITE("student:write"),
    COURSE_READ("course:read"),
    COURSE_WRITE("course:write");

    private final String appUserPermission;

    ApplicationUserPermission(String appUserPermission) {
        this.appUserPermission = appUserPermission;
    }

    public String getAppUserPermission() {
        return appUserPermission;
    }
}
