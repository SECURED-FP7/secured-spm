//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.04.19 at 01:06:33 PM CEST 
//


package main.java.mspl_class;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for RemoveAction complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="RemoveAction">
 *   &lt;complexContent>
 *     &lt;extension base="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}ConfigurationAction">
 *       &lt;sequence>
 *         &lt;element name="RemoveActionType" type="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}RemoveActionType"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "RemoveAction", propOrder = {
    "removeActionType"
})
@XmlSeeAlso({
    RemoveTrackingTechniquesAction.class,
    RemoveAdvertisementAction.class
})
public class RemoveAction
    extends ConfigurationAction
{

    @XmlElement(name = "RemoveActionType", required = true)
    protected RemoveActionType removeActionType;

    /**
     * Gets the value of the removeActionType property.
     * 
     * @return
     *     possible object is
     *     {@link RemoveActionType }
     *     
     */
    public RemoveActionType getRemoveActionType() {
        return removeActionType;
    }

    /**
     * Sets the value of the removeActionType property.
     * 
     * @param value
     *     allowed object is
     *     {@link RemoveActionType }
     *     
     */
    public void setRemoveActionType(RemoveActionType value) {
        this.removeActionType = value;
    }

}
