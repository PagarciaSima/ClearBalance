package com.clear.balance.clearBalance.domain.invoice;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import lombok.Data;

@Entity
@Data
public class InvoiceService {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String description;
    private double price;
    private int quantity;

    @ManyToOne
    @JoinColumn(
    		name = "invoice_id",
    		nullable = false,
			foreignKey = @jakarta.persistence.ForeignKey(name = "fk_invoice_service_invoice")
	)
    @JsonIgnore
    private Invoice invoice;
    
    public String getTruncatedDescription() {
        if (description == null) return "";
        
        int maxLength = 32; 
        
        if (description.length() <= maxLength) {
            return description;
        } else {
            return description.substring(0, maxLength - 3) + "...";
        }
    }
}

