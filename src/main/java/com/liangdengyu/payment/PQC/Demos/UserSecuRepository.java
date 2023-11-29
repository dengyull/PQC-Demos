package com.liangdengyu.payment.PQC.Demos;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserSecuRepository extends JpaRepository<UserSecu, Long> {
    Optional<UserSecu> findByUsername(String username);

}
