//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.4-2 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2015.11.18 at 02:29:52 PM CET 
//


package eu.fp7.secured.mspl;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for CountAction complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CountAction">
 *   &lt;complexContent>
 *     &lt;extension base="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}ConfigurationAction">
 *       &lt;sequence>
 *         &lt;element name="CountActionType" type="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}CountActionType"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CountAction", propOrder = {
    "countActionType"
})
public class CountAction
    extends ConfigurationAction
{

    @XmlElement(name = "CountActionType", required = true)
    protected CountActionType countActionType;

    /**
     * Gets the value of the countActionType property.
     * 
     * @return
     *     possible object is
     *     {@link CountActionType }
     *     
     */
    public CountActionType getCountActionType() {
        return countActionType;
    }

    /**
     * Sets the value of the countActionType property.
     * 
     * @param value
     *     allowed object is
     *     {@link CountActionType }
     *     
     */
    public void setCountActionType(CountActionType value) {
        this.countActionType = value;
    }

}
