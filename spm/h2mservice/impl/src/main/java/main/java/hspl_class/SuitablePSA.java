//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.02.29 at 10:28:31 AM CET 
//


package main.java.hspl_class;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for suitablePSA complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="suitablePSA">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="capability" type="{http://www.example.org/Refinement_Schema}capability"/>
 *         &lt;element name="psa_list" type="{http://www.example.org/Refinement_Schema}PSA_list"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "suitablePSA", propOrder = {
    "capability",
    "psaList"
})
public class SuitablePSA {

    @XmlElement(required = true)
    protected Capability capability;
    @XmlElement(name = "psa_list", required = true)
    protected PSAList psaList;

    /**
     * Gets the value of the capability property.
     * 
     * @return
     *     possible object is
     *     {@link Capability }
     *     
     */
    public Capability getCapability() {
        return capability;
    }

    /**
     * Sets the value of the capability property.
     * 
     * @param value
     *     allowed object is
     *     {@link Capability }
     *     
     */
    public void setCapability(Capability value) {
        this.capability = value;
    }

    /**
     * Gets the value of the psaList property.
     * 
     * @return
     *     possible object is
     *     {@link PSAList }
     *     
     */
    public PSAList getPsaList() {
        return psaList;
    }

    /**
     * Sets the value of the psaList property.
     * 
     * @param value
     *     allowed object is
     *     {@link PSAList }
     *     
     */
    public void setPsaList(PSAList value) {
        this.psaList = value;
    }

}
