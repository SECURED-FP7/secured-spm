#/bin/bash

BASEDIR=dansguardian_universal

ORIGINAL="/home/psa/etc/"
NEW="/home/psa/etc/dansguardian/"

if [[ ! -z $1 && -d $1 ]] ; then
    BASEDIR=$1
elif [[ ! -z $1 && ! -d $1 ]] ; then
    echo Directory $1 invalid
    exit -2
fi

if [ ! -d $BASEDIR ] ; then
    echo Please change to the proper directory
    exit -1
fi

cd $BASEDIR

for f in `find -type f | grep -v html` ; do
    grep "$ORIGINAL" $f > /dev/null
    if [ $? -eq 0 ] ; then
        echo Converting file $BASEDIR/$f
        cat $f | sed s%$ORIGINAL%$NEW%g > /tmp/polla
        mv /tmp/polla $f
    fi
done
