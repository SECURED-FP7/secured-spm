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
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for RemoveTrackingTechniquesAction complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="RemoveTrackingTechniquesAction">
 *   &lt;complexContent>
 *     &lt;extension base="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}RemoveAction">
 *       &lt;sequence>
 *         &lt;element name="RemoveTrackingTechniquesActionType" type="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}RemoveTrackingTechniquesActionType"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "RemoveTrackingTechniquesAction", propOrder = {
    "removeTrackingTechniquesActionType"
})
public class RemoveTrackingTechniquesAction
    extends RemoveAction
{

    @XmlElement(name = "RemoveTrackingTechniquesActionType", required = true)
    protected RemoveTrackingTechniquesActionType removeTrackingTechniquesActionType;

    /**
     * Gets the value of the removeTrackingTechniquesActionType property.
     * 
     * @return
     *     possible object is
     *     {@link RemoveTrackingTechniquesActionType }
     *     
     */
    public RemoveTrackingTechniquesActionType getRemoveTrackingTechniquesActionType() {
        return removeTrackingTechniquesActionType;
    }

    /**
     * Sets the value of the removeTrackingTechniquesActionType property.
     * 
     * @param value
     *     allowed object is
     *     {@link RemoveTrackingTechniquesActionType }
     *     
     */
    public void setRemoveTrackingTechniquesActionType(RemoveTrackingTechniquesActionType value) {
        this.removeTrackingTechniquesActionType = value;
    }

}
