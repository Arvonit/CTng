package monitor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TODO: Update
func TestHandleREV(t *testing.T) {
	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
    // pass 'nil' as the third parameter
	req, err := http.NewRequest("GET", "/rev", nil)
    if err != nil {
        t.Fatal(err)
    }

	// Create the HTTP endpoint
	endpoint := createRequestHandler("../testData/monitordata/1/REV_FULL.json")

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(endpoint)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method directly and pass 
	// in our Request and ResponseRecorder
	handler.ServeHTTP(rr, req)
	
	// Check the status code is what we expect
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the response body is in the format of a json array
	response := rr.Body.String()
	// if !strings.HasPrefix(response, "[\n  {") && !strings.HasSuffix(response, "}\n]") {
	// 	t.Errorf("Handler returned unexpected body: got \n%v", rr.Body.String())
	// }

	var jsonResponse json.RawMessage
    if json.Unmarshal([]byte(response), &jsonResponse) != nil {
		t.Errorf("Handler returned unexpected body: got \n%v", response)
	}
}
