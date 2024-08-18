package ru.itmentor.spring.boot_security.demo.start;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import ru.itmentor.spring.boot_security.demo.repository.RoleRepository;
import ru.itmentor.spring.boot_security.demo.repository.UserRepository;
import ru.itmentor.spring.boot_security.demo.model.Role;
import ru.itmentor.spring.boot_security.demo.model.User;

import java.util.HashSet;
import java.util.Set;

@Component
public class StartedTableData implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
private final PasswordEncoder passwordEncoder;

    @Autowired
    public StartedTableData(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    public void run(String... args) {
        Role adminrole = new Role(1L, "ROLE_ADMIN");
        Role userrole = new Role(2L, "ROLE_USER");
        roleRepository.save(adminrole);
        roleRepository.save(userrole);

        Set<Role> admin_roles = new HashSet<>();
        admin_roles.add(adminrole);

        String encodedAdminPassword = passwordEncoder.encode("admin");
        User admin = new User(1L, "admin", 48, "admin@ex.com",  encodedAdminPassword, admin_roles);
        userRepository.save(admin);

        Set<Role> user_roles = new HashSet<>();
        user_roles.add(userrole);

        String encodedUserPassword = passwordEncoder.encode("user");
        User user = new User(2L, "user", 22, "user@ex.com", encodedUserPassword, user_roles);
        userRepository.save(user);

    }
}
