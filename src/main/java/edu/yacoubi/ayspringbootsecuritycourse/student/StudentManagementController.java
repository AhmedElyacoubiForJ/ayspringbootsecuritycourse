package edu.yacoubi.ayspringbootsecuritycourse.student;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {
    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Maria Jones"),
            new Student(3, "Anna Smith")
    );

    @GetMapping
    public List<Student> getAll() {
        System.out.println("getAll()");
        return STUDENTS;
    }

    @PostMapping
    public void register(@RequestBody Student student) {
        System.out.println("register()");
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    public void delete(@PathVariable("studentId") Integer studentId) {
        System.out.println("delete()");
        System.out.println(studentId);
    }

    @PutMapping(path = "{studentId}")
    public void update(
            @PathVariable("studentId") Integer studentId,
            @RequestBody Student student
    ) {
        System.out.println("update()");
        System.out.print(String.format("%s , %s", studentId, student));
    }
}
