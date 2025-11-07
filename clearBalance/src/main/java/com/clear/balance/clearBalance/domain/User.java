package com.clear.balance.clearBalance.domain;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(content = Include.NON_DEFAULT)
@Entity
@Table(name = "users") 
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(columnDefinition = "BIGINT UNSIGNED")
    private Long id;

    @NotEmpty(message = "First name is required")
    @Column(name = "first_name", nullable = false)
    private String firstName;

    @NotEmpty(message = "Last name is required")
    @Column(name = "last_name", nullable = false)
    private String lastName;

    @NotEmpty(message = "Email is required")
    @Email(message = "Invalid email. Please enter a valid email address")
    @Column(nullable = false, unique = true)
    private String email;

    @NotEmpty(message = "Password is required")
    @Column(nullable = false)
    private String password;

    @Column
    private String address;

    @Column
    private String phone;

    @Column
    private String title;

    @Column
    private String bio;

    @Column(name = "image_url", nullable = false)
    @Builder.Default
    private String imageUrl = "https://cdn-icons-png.flaticon.com/512/149/149071.png";

    @Column
    @Builder.Default
    private boolean enabled = false;

    @Column(name = "non_locked")
    @Builder.Default
    private boolean notLocked = true;

    @Column(name = "using_mfa")
    @Builder.Default
    private boolean usingMfa = false;

    @Column(name = "created_at")
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL)
    @EqualsAndHashCode.Exclude
    private UserRole userRole;
}
