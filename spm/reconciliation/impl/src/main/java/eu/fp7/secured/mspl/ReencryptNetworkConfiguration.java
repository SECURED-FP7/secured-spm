//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.04.20 at 05:38:59 PM CEST 
//


package eu.fp7.secured.mspl;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for reencryptNetworkConfiguration complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="reencryptNetworkConfiguration">
 *   &lt;complexContent>
 *     &lt;extension base="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}AdditionalNetworkConfigurationParameters">
 *       &lt;attribute name="reencryption_strategy" type="{http://www.w3.org/2001/XMLSchema}string" />
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "reencryptNetworkConfiguration")
public class ReencryptNetworkConfiguration
    extends AdditionalNetworkConfigurationParameters
{

    @XmlAttribute(name = "reencryption_strategy")
    protected String reencryptionStrategy;

    /**
     * Gets the value of the reencryptionStrategy property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getReencryptionStrategy() {
        return reencryptionStrategy;
    }

    /**
     * Sets the value of the reencryptionStrategy property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setReencryptionStrategy(String value) {
        this.reencryptionStrategy = value;
    }

}
