const express = require('express');
const bodyParser = require('body-parser');
const app = express();

// Optionally used to retrieve additional FHIR data
const axios = require('axios'); 
const fhir = require('fhir.js');

// Optionaly used to verify tokens
const jsrJWT = require('jsrsasign');
const jwt = require('jsonwebtoken'); 
const jwkToPem = require('jwk-to-pem');


// This is necessary middleware to parse JSON into the incoming request body for POST requests
app.use(bodyParser.json());

/**
 * Security Considerations:
 * - CDS Services must implement CORS in order to be called from a web browser
 */
app.use((request, response, next) => {
  response.setHeader('Access-Control-Allow-Origin', 'https://sandbox.cds-hooks.org');
  response.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  response.setHeader('Access-Control-Allow-Credentials', 'true');
  response.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  response.setHeader('Access-Control-Expose-Headers', 'Origin, Accept, Content-Location, ' +
    'Location, X-Requested-With');

  // Pass to next layer of middleware
  next();
});

/**
 * Authorization.
 * - CDS Services should only allow calls from trusted CDS Clients
 */
app.use((request, response, next) => {
  // Always allow OPTIONS requests as part of CORS pre-flight support.
  if (request.method === 'OPTIONS') {
    next();
    return;
  }

  const serviceHost = request.get('Host');
  const authorizationHeader = request.get('Authorization');

  if (!authorizationHeader || !authorizationHeader.startsWith('Bearer')) {
    response.set('WWW-Authenticate', `Bearer realm="${serviceHost}", error="invalid_token", error_description="No Bearer token provided."`)
    return response.status(401).end();
  }

  const token = authorizationHeader.replace('Bearer ', '');
  const aud = `${request.protocol}://${serviceHost}${request.originalUrl}`;

  const publicKeySet = {
    "keys": [
      {
        "kty": "EC",
        "use": "sig",
        "crv": "P-384",
        "kid": "44823f3d-0b01-4a6c-a80e-b9d3e8a7226f",
        "x": "dw_JGR8nB2I6XveNxUOl2qk699ZPLM2nYI5STSdiEl9avAkrm3CkfYMbrrjr8laB",
        "y": "Sm3mLE-n1zYNla_aiE3cb3nZsL51RbC7ysw3q8aJLxGm-hx79RPMYpITDjp7kgzy",
        "alg": "ES384"
      }
    ]
  };

  // Verification via jsrassign
  //////////////////////////////
  // const key = jsrJWT.KEYUTIL.getKey(publicKeySet.keys[0]);

  // const isValid = jsrJWT.jws.JWS.verifyJWT(token, key, {
  //   alg: ['ES384', 'RS384'],
  //   iss: ['https://sandbox.cds-hooks.org'],
  //   aud: [aud],
  //   gracePeriod: 5 * 60  // accept 5 minutes grace period
  // });

  // if (!isValid) {
  //   response.set('WWW-Authenticate', `Bearer realm="${serviceHost}", error="invalid_token", error_description="The token is invalid."`)
  //   return response.status(401).end();
  // }

  //Verification via jsonwebtoken and jwk-to-pem
  //////////////////////////////

  const pem = jwkToPem(publicKeySet.keys[0]);
  const options = {
    algorithms: ['ES384', 'RS384'],
    audience: aud,
    issuer: ['https://sandbox.cds-hooks.org'],
    clockTolerance:  5 * 60 // accept 5 minutes grace period
  };

  try {
    const decoded = jwt.verify(token, pem, options);
    console.log("decoded: " + JSON.stringify(decoded, null, 2));
  } catch (err) {
    console.log("error: " + err);
    response.set('WWW-Authenticate', `Bearer realm="${serviceHost}", error="invalid_token", error_description="The token is invalid."`)
    return response.status(401).end();
  }

  // Pass to next layer of middleware
  next();
})

/**
 * Discovery Endpoint:
 * - A GET request to the discovery endpoint, or URL path ending in '/cds-services'
 * - This function should respond with definitions of each CDS Service for this app in JSON format
 * - See details here: http://cds-hooks.org/specification/1.0/#discovery
 */
app.get('/cds-services', (request, response) => {

  // Example service to invoke the patient-view hook
  const patientViewExample = {
    hook: 'patient-view',
    id: 'patient-view-example',
    title: 'Example patient-view CDS Service',
    description: 'Displays the name and gender of the patient',
    prefetch: {
      // Request the Patient FHIR resource for the patient in context, where the EHR fills out the prefetch template
      // See details here: http://cds-hooks.org/specification/1.0/#prefetch-template
      requestedPatient: 'Patient/{{context.patientId}}'
    }
  };

  const patientViewHypertension = {
    hook: 'patient-view',
    id: 'patient-view-hypertension',
    title: 'Example patient-view CDS Service for hypertension',
    description: 'Returns a warning if the patient has hypertension'
  };

  // Example service to invoke the order-select hook
  const orderSelectExample = {
    hook: 'order-select',
    id: 'order-select-example',
    title: 'Example order-select CDS Service',
    description: 'Suggests prescribing Aspirin 81 MG Oral Tablets',
  };

  const discoveryEndpointServices = {
    services: [ patientViewExample, patientViewHypertension, orderSelectExample ]
  };
  response.send(JSON.stringify(discoveryEndpointServices, null, 2));
});

/**
 * Patient View Example Service:
 * - Handles POST requests to our patient-view-example endpoint
 * - This function should respond with an array of card(s) in JSON format for the patient-view hook
 *
 * - Service purpose: Display a patient's first and last name, with a link to the CDS Hooks web page
 */
app.post('/cds-services/patient-view-example', (request, response) => {

  // Parse the request body for the Patient prefetch resource
  const patientResource = request.body.prefetch.requestedPatient;

  const patientViewCard = {
    cards: [
      {
        // Use the patient's First and Last name
        summary: 'Now seeing: ' + patientResource.name[0].given[0] + ' ' + patientResource.name[0].family[0],
        detail: 'Patient birthdate: ' + patientResource.birthDate,
        indicator: 'info',
        source: {
          label: 'CDS Service Tutorial',
          url: 'https://github.com/cerner/cds-services-tutorial/wiki/Patient-View-Service'
        },
        links: [
          {
            label: 'Learn more about CDS Hooks',
            url: 'http://cds-hooks.org',
            type: 'absolute'
          },
          {
            label: 'Launch SMART App!',
            url: 'https://engineering.cerner.com/smart-on-fhir-tutorial/example-smart-app/launch.html', // https://dennispatterson.github.io/smart-on-fhir-tutorial/example-smart-app/launch.html
            type: 'smart'
          }
        ]
      }
    ]
  };
  response.send(JSON.stringify(patientViewCard, null, 2));
});

/**
 * Return a warning card if the patient has hypertension.
 */
app.post('/cds-services/patient-view-hypertension', (request, response) => {
  
  const fhirServer = request.body.fhirServer;
  const patientId = request.body.context.patientId;
  const fhirAuthorization = request.body.fhirAuthorization;

  retrieveHypertensionConditionsFhirJs(fhirServer, patientId, fhirAuthorization)
    .then((conditionsBundle) => {
      if (conditionsBundle.entry && conditionsBundle.entry.length && conditionsBundle.entry[0].resource.resourceType == 'Condition') {

        const condition = conditionsBundle.entry[0].resource;
        const patientHypertensionCard = {
          cards: [
            {
              summary: 'Existing condition: ' + condition.code.text,
              indicator: 'warning',
              source: {
                label: 'CDS Service Tutorial',
                url: 'https://github.com/cerner/cds-services-tutorial/wiki/Exercises'
              }
            }
          ]
        };
        response.send(JSON.stringify(patientHypertensionCard, null, 2));
      }
    });

  response.status(200);
});

/**
 * Order Select Example Service:
 * - Handles POST requests to the order-select-example endpoint
 * - This function should respond with an array of cards in JSON format for the order-select hook
 *
 * - Service purpose: Upon a provider choosing a medication to prescribe, display a suggestion for the
 *                    provider to change their chosen medication to the service-recommended Aspirin 81 MG Oral Tablet,
 *                    or display text that affirms the provider is currently prescribing the service-recommended Aspirin
 */
app.post('/cds-services/order-select-example', (request, response) => {

  // Parse the request body for the FHIR context provided by the EHR. In this case, the MedicationRequest/MedicationOrder resource
  const draftOrder = request.body.context.draftOrders.entry[0].resource;
  const selections = request.body.context.selections;

  // Check if a medication was chosen by the provider to be ordered
  if (['MedicationRequest', 'MedicationOrder'].includes(draftOrder.resourceType) && selections.includes(`${draftOrder.resourceType}/${draftOrder.id}`)
    && draftOrder.medicationCodeableConcept) {
    const responseCard = createMedicationResponseCard(draftOrder); // see function below for more details
    response.send(JSON.stringify(responseCard, null, 2));
  }
  response.status(200);
});

// Example Conditions query - https://api.hspconsortium.org/cdshooksdstu2/open/Condition?patient=SMART-1288992&code=http://snomed.info/sct|1201005
// Example Conditions query - https://launch.smarthealthit.org/v/r2/fhir/Condition?patient=smart-1288992&code=http://snomed.info/sct|1201005
// Default patient with hypertension - SMART-1288992
// Alternate patient w/o hypertension - SMART-7321938

function retrieveHypertensionConditionsAxios(fhirServer, patientId, fhirAuthorization) {

  const headers = { Accept: 'application/json+fhir' };
  if (fhirAuthorization && fhirAuthorization.access_token) {
    headers.Authorization = `Bearer ${fhirAuthorization.access_token}`;
  }

  return axios.get('/Condition', {
    baseURL: fhirServer,
    params: {
      patient: patientId,
      code: 'http://snomed.info/sct|1201005'
    },
    headers: headers,
    timeout: 2000
  }).then((result) => {
    if (result.data && result.data.resourceType && result.data.resourceType === 'Bundle') {
      return result.data;
    }
    console.log('Response did not include Bundle');
  }).catch((error) => {
    console.log('Error querying for Conditions: ' + error);
  });
}

function retrieveHypertensionConditionsFhirJs(fhirServer, patientId, fhirAuthorization) {

  var config = {
    baseUrl: fhirServer
  }

  if (fhirAuthorization && fhirAuthorization.access_token) {
    config.auth = {bearer: fhirAuthorization.access_token}
  }

  const client = fhir(config);

  return client
    .search( {type: 'Condition', query: { 'patient': patientId, code: 'http://snomed.info/sct|1201005' }})
    .then(function(res){
        return res.data;
    })
    .catch(function(res){
        //Error responses
        if (res.status){
            console.log('Error', res.status);
        }

        //Errors
        if (res.message){
            console.log('Error', res.message);
        }
    });
}

/**
 * Creates a Card array based upon the medication chosen by the provider in the request context
 * @param context - The FHIR context of the medication being ordered by the provider
 * @returns {{cards: *[]}} - Either a card with the suggestion to switch medication or a textual info card
 */
function createMedicationResponseCard(context) {
  const providerOrderedMedication = context.medicationCodeableConcept.coding[0].code;

  // Check if medication being ordered is our recommended Aspirin 81 MG Oral Tablet
  if (providerOrderedMedication === '243670') {
    // Return this card if the provider has already chosen this specific medication to prescribe,
    // or the provider has chosen the suggestion to switch to this specific medication already
    return {
      cards: [
        {
          summary: 'Currently prescribing a low-dose Aspirin',
          indicator: 'info',
          source: {
            label: 'CDS Service Tutorial',
            url: 'https://github.com/cerner/cds-services-tutorial/wiki/Order-Select-Service'
          }
        }
      ]
    };
  } else {
    // 1. Copy the current MedicationRequest/MedicationOrder resource the provider intends to prescribe
    // 2. Change the medication being ordered by the provider to our recommended Aspirin 81 MG Oral Tablet
    // 3. Add a suggestion to a card to replace the provider's MedicationRequest/MedicationOrder resource with the CDS Service
    //    copy instead, if the provider clicks on the suggestion button
    let newMedicationRequest = context;
    newMedicationRequest.medicationCodeableConcept = {
      text: 'Aspirin 81 MG Oral Tablet',
      coding: [
        {
          display: 'Aspirin 81 MG Oral Tablet',
          system: 'http://www.nlm.nih.gov/research/umls/rxnorm',
          code: '243670'
        }
      ]
    };

    return {
      cards: [
        {
          summary: 'Reduce cardiovascular risks, prescribe daily 81 MG Aspirin',
          indicator: 'warning',
          suggestions: [
            {
              label: 'Switch to low-dose Aspirin',
              actions: [
                {
                  type: 'create',
                  description: 'Modifying existing medication order to be Aspirin',
                  resource: newMedicationRequest
                }
              ]
            }
          ],
          source: {
            label: 'CDS Service Tutorial',
            url: 'https://github.com/cerner/cds-services-tutorial/wiki/Order-Select-Service'
          }
        }
      ]
    };
  }
}

// Here is where we define the port for the localhost server to setup
app.listen(3000);
