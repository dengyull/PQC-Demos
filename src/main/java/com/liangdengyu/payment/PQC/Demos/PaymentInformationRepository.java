package com.liangdengyu.payment.PQC.Demos;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PaymentInformationRepository extends JpaRepository<PaymentInformation, Long>  {
	List<PaymentInformation> findBydisbursementAccount(String disbursementAccount);

}
