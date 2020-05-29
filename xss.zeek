#XSS Script

#Patterns Declaration
const XSS_patterns = ["<script>","<h1>"];

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string){

			#Compare Patterns with URI
			
			for(XSS_p in XSS_patterns){
				if(XSS_p in unescaped_URI){
			
					#Print Attacker IP
					print fmt("A potential XSS attack from: %s has been intercepted", c$id$orig_h);
					break;
				}
			}


}
