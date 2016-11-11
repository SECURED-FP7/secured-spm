//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.04.19 at 01:06:33 PM CEST 
//


package main.java.mspl_class;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for Authentication complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="Authentication">
 *   &lt;complexContent>
 *     &lt;extension base="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}TechnologyActionSecurityProperty">
 *       &lt;sequence>
 *         &lt;element name="serverAuthenticationMechanism" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="clientAuthenticationMechanism" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="peerAuthenticationMechanism" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "Authentication", propOrder = {
    "serverAuthenticationMechanism",
    "clientAuthenticationMechanism",
    "peerAuthenticationMechanism"
})
public class Authentication
    extends TechnologyActionSecurityProperty
{

    protected String serverAuthenticationMechanism;
    protected String clientAuthenticationMechanism;
    protected String peerAuthenticationMechanism;

    /**
     * Gets the value of the serverAuthenticationMechanism property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getServerAuthenticationMechanism() {
        return serverAuthenticationMechanism;
    }

    /**
     * Sets the value of the serverAuthenticationMechanism property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setServerAuthenticationMechanism(String value) {
        this.serverAuthenticationMechanism = value;
    }

    /**
     * Gets the value of the clientAuthenticationMechanism property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getClientAuthenticationMechanism() {
        return clientAuthenticationMechanism;
    }

    /**
     * Sets the value of the clientAuthenticationMechanism property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setClientAuthenticationMechanism(String value) {
        this.clientAuthenticationMechanism = value;
    }

    /**
     * Gets the value of the peerAuthenticationMechanism property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPeerAuthenticationMechanism() {
        return peerAuthenticationMechanism;
    }

    /**
     * Sets the value of the peerAuthenticationMechanism property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPeerAuthenticationMechanism(String value) {
        this.peerAuthenticationMechanism = value;
    }

}
