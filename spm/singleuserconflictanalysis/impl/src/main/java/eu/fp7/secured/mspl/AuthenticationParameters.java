//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.11.25 at 11:07:59 AM CET 
//


package eu.fp7.secured.mspl;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for AuthenticationParameters complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="AuthenticationParameters">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="psKey_value" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="psKey_path" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="ca_path" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="cert_path" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="key_path" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "AuthenticationParameters", propOrder = {
    "psKeyValue",
    "psKeyPath",
    "caPath",
    "certPath",
    "keyPath"
})
public class AuthenticationParameters {

    @XmlElement(name = "psKey_value", required = true)
    protected String psKeyValue;
    @XmlElement(name = "psKey_path", required = true)
    protected String psKeyPath;
    @XmlElement(name = "ca_path", required = true)
    protected String caPath;
    @XmlElement(name = "cert_path", required = true)
    protected String certPath;
    @XmlElement(name = "key_path", required = true)
    protected String keyPath;

    /**
     * Gets the value of the psKeyValue property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPsKeyValue() {
        return psKeyValue;
    }

    /**
     * Sets the value of the psKeyValue property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPsKeyValue(String value) {
        this.psKeyValue = value;
    }

    /**
     * Gets the value of the psKeyPath property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPsKeyPath() {
        return psKeyPath;
    }

    /**
     * Sets the value of the psKeyPath property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPsKeyPath(String value) {
        this.psKeyPath = value;
    }

    /**
     * Gets the value of the caPath property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCaPath() {
        return caPath;
    }

    /**
     * Sets the value of the caPath property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCaPath(String value) {
        this.caPath = value;
    }

    /**
     * Gets the value of the certPath property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCertPath() {
        return certPath;
    }

    /**
     * Sets the value of the certPath property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCertPath(String value) {
        this.certPath = value;
    }

    /**
     * Gets the value of the keyPath property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getKeyPath() {
        return keyPath;
    }

    /**
     * Sets the value of the keyPath property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setKeyPath(String value) {
        this.keyPath = value;
    }

}
