//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.04.20 at 05:38:59 PM CEST 
//


package eu.fp7.secured.mspl;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for EnableAction complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="EnableAction">
 *   &lt;complexContent>
 *     &lt;extension base="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}ConfigurationAction">
 *       &lt;sequence>
 *         &lt;element name="EnableActionType" type="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}EnableActionType"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "EnableAction", propOrder = {
    "enableActionType"
})
@XmlSeeAlso({
    ParentalControlAction.class,
    AnonimityAction.class
})
public class EnableAction
    extends ConfigurationAction
{

    @XmlElement(name = "EnableActionType", required = true)
    protected EnableActionType enableActionType;

    /**
     * Gets the value of the enableActionType property.
     * 
     * @return
     *     possible object is
     *     {@link EnableActionType }
     *     
     */
    public EnableActionType getEnableActionType() {
        return enableActionType;
    }

    /**
     * Sets the value of the enableActionType property.
     * 
     * @param value
     *     allowed object is
     *     {@link EnableActionType }
     *     
     */
    public void setEnableActionType(EnableActionType value) {
        this.enableActionType = value;
    }

}