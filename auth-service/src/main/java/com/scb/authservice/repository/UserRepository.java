package com.scb.authservice.repository;

import com.scb.authservice.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface  UserRepository extends JpaRepository<UserEntity, Integer> {
    UserEntity findByUsername(String userName);
}
