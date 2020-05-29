#SQLi Script

#Patterns Declaration
const sqli_patterns = ["or","OR","and","AND",";","'","SELECT","DROP"];

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string){

			#Compare Patterns with URI
			
			for(sqli_p in sqli_patterns){
				if(sqli_p in unescaped_URI){
			
					#Print Attacker IP
			
					print fmt("A potential SQL Injection attack from: %s has been intercepted", c$id$orig_h);
					break;
				}
			}


}
