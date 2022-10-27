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
import ssl
import urllib.request
import certifi
import csv

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
            default=False,
        ) 

    def run(self):
        while True:
            dataArray, err = self.readDataFromFile()
            if err is None:
                bundle_objects = []
                for _data in dataArray:
                    try:
                        if "score" not in _data:
                            _data['score'] = self.helper.connect_confidence_level
                        if validators.url(_data['value']):
                            if type(_data['label']) != list:
                                continue
                            obs1 = self._create_url_observable(
                                _data['value'], _data['description'], _data['label'], _data['score']
                            )
                            bundle_objects.extend(filter(None, [*obs1]))
                            hostname = urlparse(_data['value']).hostname
                            obs2 = self._create_domain_observable(
                                hostname, _data['description'], _data['label'], _data['score']
                            )
                            bundle_objects.extend(filter(None, [*obs2]))
                            rels = self._create_observation_relationships(
                                obs1, obs2, _data['description'], _data['label'], _data['score']
                            )
                            bundle_objects.extend(rels)
                        elif validators.domain(_data['value']):
                            if type(_data['label']) != list:
                                continue
                            obs = self._create_domain_observable(
                                _data['value'], _data['description'], _data['label'], _data['score']
                            )
                            bundle_objects.extend(filter(None, [*obs]))
                        elif validators.ipv4(_data['value']):
                            if type(_data['label']) != list:
                                continue
                            # TODO
                        elif validators.ipv6(_data['value']):
                            if type(_data['label']) != list:
                                continue
                            # TODO
                    except:
                        continue
                if len(bundle_objects) == 0:
                    self.helper.log_info("No objects to bundle")
                    time.sleep(10)
                    continue
                now = datetime.now(pytz.UTC)
                friendly_name = "vncert run @ " + now.astimezone(pytz.UTC).isoformat()
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                print (bundle_objects)
                bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
                self.helper.log_info("Sending event STIX2 bundle")

                self.helper.send_stix2_bundle(
                    bundle, 
                    work_id=work_id,
                    update=self._update_existing_data,
                )
            time.sleep(10)

    def readDataFromFile(self):
        try:
            filePath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", self.config['opencti']['token'])
            if not os.path.exists(filePath):
                f = open(filePath, "w+")
                f.close()
            dataFile = open(filePath, "r+")
            if os.path.getsize(filePath) == 0:
                return [], None
            dataArray = json.loads(dataFile.read())
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
        label: list,
        score: int,
    ) -> Iterator[stix2.Relationship]:
        """
        Create relationships between two observations
        :param target: The target observation
        :param source: The source Observation
        :param description: Description of the relationship
        :param label: Label of the relationship
        :return: Any relationships created
        """
        if source.observable and target.observable:
            yield self._create_relationship(
                rel_type="related-to",
                source_id=source.observable.id,
                target_id=target.observable.id,
                description=description,
                label=label,
                score=score,
            )

        if source.indicator and target.indicator:
            yield self._create_relationship(
                rel_type="related-to",
                source_id=source.indicator.id,
                target_id=target.indicator.id,
                description=description,
                label=label,
                score=score,
            )

    def _create_indicator(
        self,
        value: str,
        pattern: IndicatorPattern,
        description: str,
        label: list,
        score: int,
    ) -> stix2.Indicator:
        """Create an indicator
        :param value: Observable value
        :param pattern: Indicator pattern
        :param description: Description
        :param label: Label of the relationship
        :return: An indicator
        """
        return stix2.Indicator(
            pattern_type="stix",
            pattern=pattern.pattern,
            name=value,
            description=description,
            labels=label,
            confidence=score,
            object_marking_refs=[self._default_tlp],
            custom_properties=dict(
                x_opencti_score=score,
                x_opencti_main_observable_type=pattern.main_observable_type,
            ),
        )

    def _create_domain_observable(
        self,
        value: str,
        description: str,
        label: list,
        score: int,
    ) -> Observation:
        """Create an observation based on a domain name
        :param value: Domain name
        :param description: Description
        :param label: Label of the relationship
        :return: An observation
        """
        sco = stix2.DomainName(
            value=value,
            object_marking_refs=[self._default_tlp],
            custom_properties=dict(
                x_opencti_created_by_ref=self._identity["standard_id"],
                x_opencti_description=description,
                x_opencti_labels=label,
                x_opencti_score=score,
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
                label=label,
                score=score,
            )

            sro = self._create_relationship(
                rel_type="based-on",
                source_id=sdo.id,
                target_id=sco.id,
                description=description,
                label=label,
                score=score,
            )

        return Observation(sco, sdo, sro)

    def _create_relationship(
        self,
        rel_type: str,
        source_id: str,
        target_id: str,
        description: str,
        label: list,
        score: int,
    ) -> stix2.Relationship:
        """Create a relationship
        :param rel_type: Relationship type
        :param source_id: Source ID
        :param target_id: Target ID
        :param description: Description
        :return: A relationship
        """
        confidence = score
        created_by_ref = self._identity["standard_id"]

        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(rel_type, source_id, target_id),
            source_ref=source_id,
            relationship_type=rel_type,
            target_ref=target_id,
            created_by_ref=created_by_ref,
            confidence=confidence,
            description=description,
            labels=label,
            object_marking_refs=[self._default_tlp],
        )

    def _create_url_observable(
            self,
            value: str,
            description: str,
            label: list,
            score: int,
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
                    x_opencti_labels=label,
                    x_opencti_score=score,
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
                    label=label,
                    score=score,
                )

                sro = self._create_relationship(
                    rel_type="based-on",
                    source_id=sdo.id,
                    target_id=sco.id,
                    description=description,
                    label=label,
                    score=score,
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
