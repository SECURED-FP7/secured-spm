//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.02.29 at 10:28:31 AM CET 
//


package main.java.hspl_class;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for Candidates complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="Candidates">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="suitable_PSA_list" type="{http://www.example.org/Refinement_Schema}suitablePSA" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "Candidates", propOrder = {
    "suitablePSAList"
})
public class Candidates {

    @XmlElement(name = "suitable_PSA_list")
    protected List<SuitablePSA> suitablePSAList;

    /**
     * Gets the value of the suitablePSAList property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the suitablePSAList property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getSuitablePSAList().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link SuitablePSA }
     * 
     * 
     */
    public List<SuitablePSA> getSuitablePSAList() {
        if (suitablePSAList == null) {
            suitablePSAList = new ArrayList<SuitablePSA>();
        }
        return this.suitablePSAList;
    }

}
