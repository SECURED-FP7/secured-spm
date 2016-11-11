//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.04.19 at 01:06:33 PM CEST 
//


package main.java.mspl_class;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for DataProtectionAction complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="DataProtectionAction">
 *   &lt;complexContent>
 *     &lt;extension base="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}ConfigurationAction">
 *       &lt;sequence>
 *         &lt;element name="technology" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *         &lt;element name="technologyActionParameters" type="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}ActionParameters"/>
 *         &lt;element name="technologyActionSecurityProperty" type="{http://modeliosoft/xsddesigner/a22bd60b-ee3d-425c-8618-beb6a854051a/ITResource.xsd}TechnologyActionSecurityProperty" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DataProtectionAction", propOrder = {
    "technology",
    "technologyActionParameters",
    "technologyActionSecurityProperty"
})
public class DataProtectionAction
    extends ConfigurationAction
{

    @XmlElement(required = true)
    protected String technology;
    @XmlElement(required = true)
    protected ActionParameters technologyActionParameters;
    protected List<TechnologyActionSecurityProperty> technologyActionSecurityProperty;

    /**
     * Gets the value of the technology property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTechnology() {
        return technology;
    }

    /**
     * Sets the value of the technology property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTechnology(String value) {
        this.technology = value;
    }

    /**
     * Gets the value of the technologyActionParameters property.
     * 
     * @return
     *     possible object is
     *     {@link ActionParameters }
     *     
     */
    public ActionParameters getTechnologyActionParameters() {
        return technologyActionParameters;
    }

    /**
     * Sets the value of the technologyActionParameters property.
     * 
     * @param value
     *     allowed object is
     *     {@link ActionParameters }
     *     
     */
    public void setTechnologyActionParameters(ActionParameters value) {
        this.technologyActionParameters = value;
    }

    /**
     * Gets the value of the technologyActionSecurityProperty property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the technologyActionSecurityProperty property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getTechnologyActionSecurityProperty().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link TechnologyActionSecurityProperty }
     * 
     * 
     */
    public List<TechnologyActionSecurityProperty> getTechnologyActionSecurityProperty() {
        if (technologyActionSecurityProperty == null) {
            technologyActionSecurityProperty = new ArrayList<TechnologyActionSecurityProperty>();
        }
        return this.technologyActionSecurityProperty;
    }

}