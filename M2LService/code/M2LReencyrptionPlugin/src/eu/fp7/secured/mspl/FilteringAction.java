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
 * <p>Java class for FilteringAction complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="FilteringAction">
 *   &lt;complexContent>
 *     &lt;extension base="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}ConfigurationAction">
 *       &lt;sequence>
 *         &lt;element name="FilteringActionType" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "FilteringAction", propOrder = {
    "filteringActionType"
})
public class FilteringAction
    extends ConfigurationAction
{

    @XmlElement(name = "FilteringActionType", required = true)
    protected String filteringActionType;

    /**
     * Gets the value of the filteringActionType property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getFilteringActionType() {
        return filteringActionType;
    }

    /**
     * Sets the value of the filteringActionType property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setFilteringActionType(String value) {
        this.filteringActionType = value;
    }

}
