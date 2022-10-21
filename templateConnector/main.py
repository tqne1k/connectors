import os
import sys
import pytz
import time
import json
from datetime import datetime

import stix2
import yaml
import pycti
import validators
from urllib.parse import urlparse
from typing import Iterator, NamedTuple, Optional
from stix2.v21 import _Observable as Observable 
from pycti import OpenCTIConnectorHelper, get_config_variable, Identity
from patterns import (
    IndicatorPattern,
    create_indicator_pattern_domain_name,
    create_indicator_pattern_url,
)


import string
import random

class Observation(NamedTuple):
    """Result from making an observable"""

    observable: Observable
    indicator: stix2.Indicator = None
    relationship: stix2.Relationship = None

class Connector:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        self.config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(self.config)
        self._default_labels = ["Phishing", "phishfeed"]
        self.cve_interval = get_config_variable(
            "TEMPLATE_ATTRIBUTE", ["template", "attribute"], self.config, True
        )
        default_tlp = get_config_variable(
            "URLSCAN_DEFAULT_TLP",
            ["urlscan", "default_tlp"],
            self.config,
            default="white",
        )
        self._default_tlp = getattr(stix2, f"TLP_{default_tlp}".upper(), None)
        if not isinstance(self._default_tlp, stix2.MarkingDefinition):
            raise ValueError(f"Invalid tlp: {default_tlp}")
        self._identity = self.helper.api.identity.create(
            type="Organization",
            name="VNCERT",
            description="VNCERT CTI DEMO",
        )
        self._create_indicators = get_config_variable(
            "URLSCAN_CREATE_INDICATORS",
            ["urlscan", "create_indicators"],
            self.config,
            default=True,
        ) 
        self.connect_confidence_level = get_config_variable(
            "CONNECTOR_CONFIDENCE_LEVEL",
            ["connector", "confidence_level"],
            self.config,
            True,
        )
        self._update_existing_data = get_config_variable(
            "URLSCAN_UPDATE_EXISTING_DATA",
            ["urlscan", "update_existing_data"],
            self.config,
            default=True,
        ) 

    def run(self):
        while True:
            dataArray, err = self.readDataFromFile()
            if err is None:
                bundle_objects = []
                for urlData in dataArray:
                    obs1 = self._create_url_observable(urlData['url'], urlData['description'])
                    bundle_objects.extend(filter(None, [*obs1]))
                    hostname = urlparse(urlData['url']).hostname
                    if validators.domain(hostname):
                        try:
                            obs2 = self._create_domain_observable(hostname, urlData['description'])
                        except Exception as exp:
                            raise exp
                            continue
                        bundle_objects.extend(filter(None, [*obs2]))

                        rels = self._create_observation_relationships(
                            obs1, obs2, urlData['description']
                        )
                        bundle_objects.extend(rels)
                if len(bundle_objects) == 0:
                    self.helper.log_info("No objects to bundle")
                    time.sleep(10)
                    continue
                now = datetime.now(pytz.UTC)
                friendly_name = "vncert run @ " + now.astimezone(pytz.UTC).isoformat()
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
                self.helper.log_info("Sending event STIX2 bundle")

                self.helper.send_stix2_bundle(
                    bundle, 
                    work_id=work_id,
                    update=self._update_existing_data,
                )
            time.sleep(10)

    def phakeData(self):
        domains = [
            "http://phakebook.com/",
            "https://youtobe.me/",
            "http://g00gl3.xyz/",
            "http://0nlyPie.us/",
            "http://honpub.com/",
            "http://instakilogam.com/",
            "https://notDomain.tar.gz/",
            "https://bet8888.lostmonney/"
        ]
        dataArr = []
        while len(dataArr) < 10:
            domain = domains[random.randint(0, 7)]
            N = random.randint(10, 100)
            res = ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))
            dataArr.append({
                'url': domain + str(res),
                'description': "Demo data"
            })
        return dataArr

    def readDataFromFile(self):
        try:
            filePath = os.path.join(self.config['api']['api_data_path'], self.config['connector']['id'])
            dataFile = open(filePath, "r+")
            # if os.path.getsize(filePath) == 0:
            #     return [], None
            # dataArray = json.loads(dataFile.read())
            dataArray = self.phakeData()
            print (dataArray)
            dataFile.seek(0)
            dataFile.truncate()
            return dataArray, None
        except Exception as exp:
            raise exp
            self.helper.log_error(f"Can not open file! [{exp}]")
            return None, exp
        finally:
            dataFile.close()

    def _create_observation_relationships(
        self,
        target: Observation,
        source: Observation,
        description: str,
    ) -> Iterator[stix2.Relationship]:
        """
        Create relationships between two observations
        :param target: The target observation
        :param source: The source Observation
        :param description: Description of the relationship
        :return: Any relationships created
        """
        if source.observable and target.observable:
            yield self._create_relationship(
                rel_type="related-to",
                source_id=source.observable.id,
                target_id=target.observable.id,
                description=description,
            )

        if source.indicator and target.indicator:
            yield self._create_relationship(
                rel_type="related-to",
                source_id=source.indicator.id,
                target_id=target.indicator.id,
                description=description,
            )

    def _create_indicator(
        self,
        value: str,
        pattern: IndicatorPattern,
        description: str,
    ) -> stix2.Indicator:
        """Create an indicator
        :param value: Observable value
        :param pattern: Indicator pattern
        :param description: Description
        :return: An indicator
        """
        return stix2.Indicator(
            pattern_type="stix",
            pattern=pattern.pattern,
            name=value,
            description=description,
            labels=self._default_labels,
            confidence=self.helper.connect_confidence_level,
            object_marking_refs=[self._default_tlp],
            custom_properties=dict(
                x_opencti_score=self.helper.connect_confidence_level,
                x_opencti_main_observable_type=pattern.main_observable_type,
            ),
        )

    def _create_domain_observable(
        self,
        value: str,
        description: str,
    ) -> Observation:
        """Create an observation based on a domain name
        :param value: Domain name
        :param description: Description
        :return: An observation
        """
        sco = stix2.DomainName(
            value=value,
            object_marking_refs=[self._default_tlp],
            custom_properties=dict(
                x_opencti_created_by_ref=self._identity["standard_id"],
                x_opencti_description=description,
                x_opencti_labels=self._default_labels,
                x_opencti_score=self.helper.connect_confidence_level,
            ),
        )

        sdo = None
        sro = None
        if self._create_indicators:
            pattern = create_indicator_pattern_domain_name(value)
            sdo = self._create_indicator(
                value=value,
                pattern=pattern,
                description=description,
            )

            sro = self._create_relationship(
                rel_type="based-on",
                source_id=sdo.id,
                target_id=sco.id,
                description=description,
            )

        return Observation(sco, sdo, sro)

    def _create_relationship(
        self,
        rel_type: str,
        source_id: str,
        target_id: str,
        description: str,
    ) -> stix2.Relationship:
        """Create a relationship
        :param rel_type: Relationship type
        :param source_id: Source ID
        :param target_id: Target ID
        :param description: Description
        :return: A relationship
        """
        confidence = self.helper.connect_confidence_level
        created_by_ref = self._identity["standard_id"]

        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(rel_type, source_id, target_id),
            source_ref=source_id,
            relationship_type=rel_type,
            target_ref=target_id,
            created_by_ref=created_by_ref,
            confidence=confidence,
            description=description,
            labels=self._default_labels,
            object_marking_refs=[self._default_tlp],
        )

    def _create_url_observable(
            self,
            value: str,
            description: str,
        ) -> Observation:
            """Create an observation based on a URL
            :param value: URL value
            :param description: Description
            :return: An observation
            """
            sco = stix2.URL(
                value=value,
                object_marking_refs=[self._default_tlp],
                custom_properties=dict(
                    x_opencti_created_by_ref=self._identity["standard_id"],
                    x_opencti_description=description,
                    x_opencti_labels=self._default_labels,
                    x_opencti_score=self.helper.connect_confidence_level,
                ),
            )
            sdo = None
            sro = None
            if self._create_indicators:
                pattern = create_indicator_pattern_url(value)
                sdo = self._create_indicator(
                    value=value,
                    pattern=pattern,
                    description=description,
                )

                sro = self._create_relationship(
                    rel_type="based-on",
                    source_id=sdo.id,
                    target_id=sco.id,
                    description=description,
                )

            return Observation(sco, sdo, sro)

if __name__ == "__main__":
    try:
        connector = Connector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
