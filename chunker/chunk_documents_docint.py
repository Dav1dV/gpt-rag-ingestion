import base64
import json
import logging
import os
import re
import requests
import time
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from azure.keyvault.secrets import SecretClient
from chunker import table_utils as tb
from embedder.text_embedder import TextEmbedder
from .token_estimator import TokenEstimator
from urllib.parse import urlparse, unquote
from utils.file_utils import get_file_extension
from utils.file_utils import get_filename

##########################################################################################
# CONFIGURATION
##########################################################################################

# Chunker parameters
NUM_TOKENS = int(os.environ["NUM_TOKENS"]) # max chunk size in tokens
MIN_CHUNK_SIZE = int(os.environ["MIN_CHUNK_SIZE"]) # min chunk size in tokens
TOKEN_OVERLAP = int(os.environ["TOKEN_OVERLAP"])

# Doc int version
DOCINT_40_API = '2023-10-31-preview'
default_api_version = '2023-07-31'
DOCINT_API_VERSION = os.getenv('FORM_REC_API_VERSION', os.getenv('DOCINT_API_VERSION', default_api_version))

# Network isolation active?
NETWORK_ISOLATION = os.environ["NETWORK_ISOLATION"]
network_isolation = True if NETWORK_ISOLATION.lower() == 'true' else False

# Supported file extensions
FILE_EXTENSION_DICT = [
    "pdf",
    "bmp",
    "jpeg",
    "png",
    "tiff"
]
if DOCINT_API_VERSION >= DOCINT_40_API:
    formrec_or_docint = "documentintelligence"
    FILE_EXTENSION_DICT.extend(["docx", "pptx", "xlsx", "html"])
else:
    formrec_or_docint = "formrecognizer"

TOKEN_ESTIMATOR = TokenEstimator()

##########################################################################################
# UTILITY FUNCTIONS
##########################################################################################

def check_timeout(start_time):
    max_time = 230 # webapp timeout is 230 seconds
    elapsed_time = time.time() - start_time
    if elapsed_time > max_time:
        return True
    else:
        return False    

def indexer_error_message(error_type, exception=None):
    error_message = "no error message"
    if error_type == 'timeout':
        error_message =  "Terminating the function so it doesn't run indefinitely. The AI Search indexer's timout is 3m50s. If the document is large (more than 100 pages), try dividing it into smaller files. If you are encountering many 429 errors in the function log, try increasing the embedding model's quota as the retrial logic delays processing."
    elif error_type == 'embedding':
        error_message = "Error when embedding the chunk, if it is a 429 error code please consider increasing your embeddings model quota: " + str(exception)
    logging.info(f"Error: {error_message}")
    return {"message": error_message}

def has_supported_file_extension(file_path: str) -> bool:
    """Checks if the given file format is supported based on its file extension.
    Args:
        file_path (str): The file path of the file whose format needs to be checked.
    Returns:
        bool: True if the format is supported, False otherwise.
    """
    file_extension = get_file_extension(file_path)
    return file_extension in FILE_EXTENSION_DICT

# def get_content_type(file_ext):
#     extensions = {
#         "pdf": "application/pdf",
#         "bmp": "image/bmp",
#         "jpeg": "image/jpeg",
#         "png": "image/png",
#         "tiff": "image/tiff",
#         "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
#         "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
#         "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
#         "html": "text/html"
#     }
#     if file_ext in extensions:
#         return extensions[file_ext]
#     else:
#         return "application/octet-stream"

def get_secret(secretName):
    keyVaultName = os.environ["AZURE_KEY_VAULT_NAME"]
    KVUri = f"https://{keyVaultName}.vault.azure.net"
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=KVUri, credential=credential)
    logging.info(f"Retrieving {secretName} secret from {keyVaultName}.")   
    retrieved_secret = client.get_secret(secretName)
    return retrieved_secret.value

##########################################################################################
# DOCUMENT INTELLIGENCE ANALYSIS
##########################################################################################

def analyze_document_rest(filepath, filename, model):

    result = {}
    errors = []

    # TODO Use Doc Int SDK instead of lower-level requests?  https://pypi.org/project/azure-ai-documentintelligence

    if get_file_extension(filename) in ["pdf"]:
        docint_features = "ocrHighResolution"
    else:
        docint_features = ""

    request_endpoint = f"https://{os.environ['AZURE_FORMREC_SERVICE']}.cognitiveservices.azure.com/{formrec_or_docint}/documentModels/{model}:analyze?api-version={DOCINT_API_VERSION}&features={docint_features}&includeKeys=true"
    # https://learn.microsoft.com/en-us/rest/api/aiservices/document-models/analyze-document?view=rest-aiservices-2023-07-31
    # TODO includeKeys appears to be no longer applicable since API version 2.0

    headers = {
        "Content-Type": "application/json",
        "Ocp-Apim-Subscription-Key": get_secret('formRecKey'),
        "x-ms-useragent": "gpt-rag/1.0.0"
    }

    def request():
        return requests.post(request_endpoint, headers=headers, json=body)

    def add_error(message):
        logging.error(error_message)
        errors.append(error_message)

    def abort(message, callback):
        add_error(message)
        if callback:
            callback()
        return result, errors

    if not network_isolation:
        body = {
            "urlSource": filepath
        }
    else:
        # With network isolation,  Doc Int can't access container with no public access
        # so download it & send its content as a stream.

        parsed_url = urlparse(filepath)
        account_url = parsed_url.scheme + "://" + parsed_url.netloc
        container_name = unquote(parsed_url.path.split("/")[1])
        blob_name = filename

        logging.info(f"Connecting to blob to get `{blob_name}`.")

        credential = DefaultAzureCredential()
        blob_service_client = BlobServiceClient(account_url=account_url, credential=credential)
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)

#        # TODO Remove debug
#        blob = blob_client.download_blob().readall()
#        logging.info(f'POST {request_endpoint}')
#        logging.info(f'headers={headers}')
#        def test_docint(base64_source):
#            body = {
#                "base64Source": base64_source
#            }
#            logging.info(f'body={body}')
#            def _test(body):
#                response = requests.post(request_endpoint, headers=headers, json=body)
#                logging.error(    f"Document Intelligence API response:        {response}")
#                if response is not None:
#                    logging.error(f"Document Intelligence API response:        {response.status_code} {response.reason} {response.text}")
#                    logging.error(f"Document Intelligence API response request:{response.request}")
#            try:
#                _test(body)
#            except Exception as e:
#                logging.error(e)
#
#            try:
#                _test(json.dumps(body))
#            except Exception as e:
#                logging.error(e)
#        test_docint(blob)
#        test_docint(base64.urlsafe_b64encode(blob))
#        test_docint(base64.urlsafe_b64encode(blob).decode())
#        test_docint(base64.b64encode(blob))
#        test_docint(base64.b64encode(blob).decode())

        try:
            body = {
                "base64Source": base64.b64encode( blob_client.download_blob().readall() ).decode()
                # base64.urlsafe_b64encode output results in HTTP 400 error
                #   {"error": {"code":"InvalidRequest", "message":"Invalid request.", "innererror":{
                #     "code":"InvalidContent", "message":"The file is corrupted or format is unsupported. Refer to documentation for the list of supported formats."}}}
            }
            # instead of:
            # data = blob_client.download_blob().readall()
            # file_ext = blob_name.split(".")[-1]
            # headers['Content-Type'] = get_content_type(file_ext)
            # def request():
            #     return requests.post(request_endpoint, headers=headers, data=data)
        except Exception as blob_error:
            return abort("Blob client error when reading from blob storage:  {blob_error}")

    retries       = 1
    retry_seconds = 10
    response      = None
    request_error = None
    for i in range(retries):
        try:
            try:
                # Send request
                # TODO Debug remove - debug level logging already being done lower
#                logging.info(f'POST {request_endpoint}')
#                logging.info(f'headers={headers}')
#                logging.info(f'body={body}')
                response = request()
                break
            except requests.exceptions.ConnectionError as conn_error:
                logging.warning(f"Connection error, retrying in {retry_seconds} seconds...:  {conn_error}")
                time.sleep(retry_seconds)
                raise conn_error
        except Exception as e:
            request_error = e

    if response is None  or  response.status_code != 202:
        # Request failed
        error_message =   f"Document Intelligence request error:   {f'code={response.status_code} reason=`{response.reason}` text=`{response.text}`' if response  else request_error}"
        def log_details():
            logging.error(f"filepath:  {filepath}")
            logging.debug(f"Document Intelligence request URL:     {request_endpoint}")
            logging.debug(f"Document Intelligence request headers: {headers}")
            logging.debug(f"Document Intelligence request body:    {body}")
        return abort(error_message, log_details)

    # Poll for result
    get_url = response.headers["Operation-Location"]
    result_headers = headers.copy()
    result_headers["Content-Type"] = "application/json-patch+json"

    while True:
        result_response = requests.get(get_url, headers=result_headers)
        result_json = json.loads(result_response.text)

        if result_response.status_code != 200 or result_json["status"] == "failed":
            # Request failed
            error_message = f"Doc Intelligence polling error, code {result_response.status_code}: {response.text}"
            add_error(error_message)
            break

        if result_json["status"] == "succeeded":
            result = result_json['analyzeResult']
            break

        # Request still processing, wait and try again
        time.sleep(2)

    return result, errors

##########################################################################################
# CHUNKING FUNCTIONS
########################################################################################## 

def get_chunk(content, url, page, chunk_id, text_embedder):

    chunk =  {
            "chunk_id": chunk_id,
            "offset": 0,
            "length": 0,
            "page": page,                    
            "title": "default",
            "category": "default",
            "url": url,
            "filepath": unquote(get_filename(url)),
            "content": content,
            "contentVector": text_embedder.embed_content(content)
    }
    logging.info(f"Chunk: {chunk}.")
    return chunk

def chunk_document(data):
    chunks = []
    errors = []
    warnings = []
    chunk_id = 0
    error_occurred = False
    start_time = time.time()

    text_embedder = TextEmbedder()
    document_url  = data['documentUrl']
    filepath      = f"{document_url}{data['documentSasToken']}"
    doc_name = data.filename

    # 1) Analyze document with layout model
    logging.info(f"Analyzing `{doc_name}`.")
    document, analysis_errors = analyze_document_rest(filepath, doc_name, 'prebuilt-layout')
    if len(analysis_errors) > 0:
        errors = errors + analysis_errors
        error_occurred = True

    # 2) Check number of pages
    if 'pages' in document and not error_occurred:
        n_pages = len(document['pages'])
        logging.info(f"Analyzed {doc_name} ({n_pages} pages). Content: {document['content'][:200]}.") 
        pages_max_recommended = 100
        if n_pages > pages_max_recommended:
            logging.warn(f"DOCUMENT `{doc_name}` HAS MANY PAGES ({n_pages}).  Please consider splitting it into smaller documents of <{pages_max_recommended} pages.")


    def add_error(error_type, exception=None):
        nonlocal errors, error_occurred
        errors.append(indexer_error_message(error_type, exception))
        error_occurred = True

    def add_chunk():
        nonlocal chunk_id, chunks, chunk_content, document_url, page, text_embedder
        chunk_id += 1
        try:
            chunks.append(get_chunk(chunk_content, document_url, page, chunk_id, text_embedder))
        except Exception as e:
            add_error('embedding', e)
            raise e

    # 3) Chunk tables
    if 'tables' in document and not error_occurred:

        # 3.1) merge consecutive tables if they have the same structure 
        
        document["tables"] = tb.merge_tables_if_same_structure(document["tables"], document["pages"])

        # 3.2) create chunks for each table
        
        processed_tables = []
        for idx, table in enumerate(document["tables"]):
            if idx not in processed_tables:
                processed_tables.append(idx)
                # TODO: check if table is too big for one chunck and split it to avoid truncation
                chunk_content = tb.table_to_html(table)

                # page number logic
                page = 1
                bounding_regions = table['cells'][0].get('boundingRegions')
                if bounding_regions is not None:
                    page = bounding_regions[0].get('pageNumber', 1)

                # if there is text before the table add it to the beggining of the chunk to improve context.
                text = tb.text_before_table(document, table, document["tables"])
                chunk_content = text + chunk_content

                # if there is text after the table add it to the end of the chunk to improve context.
                text = tb.text_after_table(document, table, document["tables"])
                chunk_content = chunk_content + text
                try:
                    add_chunk()
                except Exception as e:
                    break

                if check_timeout(start_time):
                    add_error('timeout')
                    break

    # 4) Chunk paragraphs
    if 'paragraphs' in document and not error_occurred:    
        chunk_content = ''

        for paragraph in document['paragraphs']:

            # page number logic
            page = 1
            bounding_regions = paragraph.get('boundingRegions')
            if bounding_regions is not None:
                page = bounding_regions[0].get('pageNumber', 1)

            if not tb.paragraph_in_a_table(paragraph, document['tables']):
                paragraph_content_to_append = '\n' + paragraph['content']
                chunk_content_expanded      = chunk_content + paragraph_content_to_append
                chunk_content_expanded_size = TOKEN_ESTIMATOR.estimate_tokens(chunk_content_expanded)
                if chunk_content_expanded_size < NUM_TOKENS:
                    chunk_content = chunk_content_expanded
                else:
                    if len(chunk_content) > 0:
                        try:
                            add_chunk()
                        except Exception as e:
                            break

                        # overlap logic
                        chunk_content = ' '.join(chunk_content.split()[-round(TOKEN_OVERLAP/0.75):])

                    chunk_content += paragraph_content_to_append
                    # TODO ?If estimate_tokens(chunk_content) ≥ NUM_TOKENS, subdivide chunk_content into multiple chunks?

                    if check_timeout(start_time):
                        add_error('timeout')
                        break

        if not error_occurred:
            # last section
            # chunk_size = TOKEN_ESTIMATOR.estimate_tokens(paragraph_content)
            try:
                # if chunk_size > MIN_CHUNK_SIZE:
                #     add_chunk()
                add_chunk()
            except Exception as e:
                add_error('embedding', e)
    
    logging.info(f"Finished chunking `{doc_name}`. {len(chunks)} chunks. {len(errors)} errors. {len(warnings)} warnings.")

    return chunks, errors, warnings
