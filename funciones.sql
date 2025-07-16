-- Funcion que nos permite validar si un servidor PostgreSQL tiene habilitado el TLS 


-- DROP FUNCTION pgtlsinfo(TEXT,INT,INT,TEXT,TEXT);
CREATE OR REPLACE FUNCTION pgtlsinfo(
										p_ip_server_or_certificate TEXT DEFAULT '',
										p_port INT DEFAULT 5432,
										p_timeout INT DEFAULT 2/*,
										p_tls_version TEXT DEFAULT '1.3',
										p_cipher TEXT DEFAULT 'TLS_AES_256_GCM_SHA384'*/
									)
RETURNS 
TABLE( ip_server INET, 
       port INT, 
	   connect_server  BOOLEAN, 
	   tls_enabled BOOLEAN, 
	   tls_version TEXT, 
	   cipher TEXT, 
	   issuer TEXT, 
	   subject TEXT , 
	   key_usage TEXT,
       extended_key_usage TEXT,
	   alternative_name TEXT, 
	   basic_constraints TEXT,
	   cert_type TEXT,
	   date_before TIMESTAMP, 
	   date_after TIMESTAMP, 
	   path TEXT,
	   is_file BOOLEAN,
	   certificate  TEXT,
	   openssl_output TEXT
	  )
AS $_$
DECLARE
	v_exec_openssl TEXT;
    v_openssl_local TEXT := 'openssl x509 -in %L -text -noout' ;
	v_openssl_remote TEXT := 'echo | timeout %s openssl s_client -connect %s:%s -starttls postgres -status  -showcerts  2>&1 | cat ' ;
	v_save_exec_table_cert TEXT := E'COPY tmp_tb_openssl(clm_certificate) from  PROGRAM $__$ %s $__$ WITH (DELIMITER ''^'');';
	v_save_exec_table_openssl TEXT := E'COPY tmp_tb_openssl(clm_openssl_output) from  PROGRAM $__$ %s $__$ WITH (DELIMITER ''^'');';
    v_get_cert TEXT :=  'echo "%s" | openssl x509 -noout -text';
	v_result_certificate TEXT;
	v_element_foreach TEXT;
	v_parse_x509_info RECORD;
	v_status_error BOOLEAN := true;
	
	
BEGIN

	--DROP TABLE IF EXISTS tmp_tb_openssl;
 	create  temporary table  tmp_tb_openssl -- select * from tmp_tb_openssl;
	(	
		clm_certificate TEXT,
		clm_openssl_output TEXT
	);  
 
	-- Validar un archivo certificado de manera local	

	IF ( p_ip_server_or_certificate = '' or file_exists(p_ip_server_or_certificate) ) THEN
		IF ( p_ip_server_or_certificate = '' ) THEN
			v_exec_openssl :=  FORMAT(v_openssl_local , (select setting from pg_settings where name = 'ssl_cert_file') );
		ELSEIF  file_exists(p_ip_server_or_certificate) THEN 		
			v_exec_openssl := FORMAT(v_openssl_local,p_ip_server_or_certificate);
		END IF;
		
		v_status_error := false;
		EXECUTE FORMAT(v_save_exec_table_cert, v_exec_openssl );		
		select  string_agg(clm_certificate,E'\n') into v_result_certificate from tmp_tb_openssl;
	
		--RAISE NOTICE 'Texto %',v_result_certificate;
		
		
		-- En este caso se coloca * porque se puede si se especifica los nombres se tendra problemas de ambiguedad
		select * into v_parse_x509_info from parse_x509_info(v_result_certificate);
		
		issuer := v_parse_x509_info.issuer;
		subject := v_parse_x509_info.subject;
		key_usage := v_parse_x509_info.key_usage;
		extended_key_usage := v_parse_x509_info.extended_key_usage;
		alternative_name := v_parse_x509_info.alternative_name;
		basic_constraints := v_parse_x509_info.basic_constraints;
		date_before := v_parse_x509_info.date_before;
		date_after := v_parse_x509_info.date_after;
		certificate := v_result_certificate;
		path := (select setting from pg_settings where name = 'ssl_cert_file');
		is_file := TRUE;
		cert_type := v_parse_x509_info.cert_type;
		
		
		
		RETURN NEXT;
		
		
	END IF;

 
	-- Validar el certificado de un servidor de manera remota
	IF (select status from verify_ip_entries(p_ip_server_or_certificate)) THEN
		v_status_error := false;
		FOREACH v_element_foreach IN ARRAY (select result from verify_ip_entries(p_ip_server_or_certificate)) LOOP
			
			
			ip_server := split_part(v_element_foreach,':',1);
			IF (split_part(v_element_foreach,':',2) != '' ) THEN
				port := split_part(v_element_foreach,':',2)::INT;
			ELSE 
				port := p_port;
			END IF;
			
 
			v_exec_openssl := FORMAT(v_openssl_remote,p_timeout,ip_server,port);
			EXECUTE FORMAT(v_save_exec_table_openssl, v_exec_openssl );
			select  string_agg(clm_openssl_output,E'\n') into v_result_certificate from tmp_tb_openssl;
			---raise notice E' -> %  ',v_exec_openssl; 
			--raise notice E' -> %  ',v_result_certificate; 
			
			--select * into v_parse_x509_info from parse_x509_info(v_result_certificate);
			openssl_output := v_result_certificate;
			
			IF (v_result_certificate ~ 'refused' OR v_result_certificate is null) THEN 
				connect_server := false;
			END IF;
			
			IF (v_result_certificate ~ 'CONNECTED') THEN
				connect_server := true;
			END IF;
			
			IF (v_result_certificate ~ 'BEGIN CERTIFICATE') THEN
				tls_enabled := true;
				
				select a[1] into tls_version from  regexp_match(v_result_certificate,'New, (TLSv[0-9\.]+), Cipher' ) as a;
				select a[1] into cipher from  regexp_match(v_result_certificate,'Cipher is ([A-Z0-9_]+)') as a;
			
				 
				v_exec_openssl := FORMAT(v_get_cert, v_result_certificate );
				EXECUTE FORMAT(v_save_exec_table_cert, v_exec_openssl );
				--raise notice '%',v_exec_openssl;
				
				select  string_agg(clm_certificate,E'\n') into v_result_certificate from tmp_tb_openssl;
				select * into v_parse_x509_info from parse_x509_info(v_result_certificate);
			
				certificate := v_result_certificate;
			
				issuer := v_parse_x509_info.issuer;
				subject := v_parse_x509_info.subject;
				key_usage := v_parse_x509_info.key_usage;
				extended_key_usage := v_parse_x509_info.extended_key_usage;
				alternative_name := v_parse_x509_info.alternative_name;
				basic_constraints := v_parse_x509_info.basic_constraints;
				date_before := v_parse_x509_info.date_before;
				date_after := v_parse_x509_info.date_after;
				is_file := FALSE;
				cert_type := v_parse_x509_info.cert_type;

				
			ELSE
				tls_enabled := false;
				tls_version := NULL; 
				cipher := NULL; 
				issuer := NULL; 
				subject := NULL;
				key_usage := NULL;
				extended_key_usage := NULL;
				alternative_name := NULL; 
				basic_constraints := NULL;
				cert_type := NULL;
				date_before := NULL;
				date_after := NULL;
				path := NULL;
				is_file := NULL;
				certificate  := NULL;
				-- openssl_output := NULL;
			END IF;
			
			TRUNCATE tmp_tb_openssl;
			RETURN NEXT;
			 
		END LOOP;
	END IF;
 
	-- Validar si es una IP, listado
	
	DROP TABLE IF EXISTS tmp_tb_openssl;
	
	IF v_status_error THEN
		RAISE EXCEPTION 'al especificar la IP o el certificado';
	END IF;
	
	
	
EXCEPTION
	WHEN OTHERS THEN
	  RAISE NOTICE 'Error  %', SQLERRM; 
END;
$_$ LANGUAGE plpgsql
SET client_min_messages='notice';



-- select * from pgtlsinfo('192.168.1.100:5432');
-- select * from pgtlsinfo('127.0.0.1:5411,127.0.0.1:5414,127.0.0.1:5416');
-- select * from pgtlsinfo();
-- select * from pgtlsinfo('/sysx/data16/certserver/otros/star_certificado.crt');
-- select * from pgtlsinfo('/sysx/data16/certserver/otros/ca_certificado.crt');
-- select * from pgtlsinfo('/sysx/data16/certserver/otros/root_certificado.crt');


 
-- -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384  -cipher




-- ##########################################################################################################################################################



-- DROP FUNCTION verify_ip_entries(p_valor TEXT);
CREATE OR REPLACE FUNCTION verify_ip_entries(p_valor TEXT)
RETURNS table(status BOOLEAN, result TEXT[]) AS $$
DECLARE
  v_partes TEXT[];
  v_elemento TEXT;
BEGIN

  select array_agg(a) into v_partes from (select distinct unnest(string_to_array(public.clean_string(p_valor),',')) as a ) as a ;

  FOREACH v_elemento IN ARRAY v_partes LOOP
    -- Validar IP
    --IF v_elemento ~ '^([0-9]{1,3}\.){3}[0-9]{1,3}$' THEN
	IF v_elemento ~ '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$' THEN
      CONTINUE;

    -- Validar IP:Puerto
    ELSIF v_elemento ~ '^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$' THEN
      CONTINUE;

    -- Si no cumple ninguno, es inválido
    ELSE
      RETURN QUERY SELECT FALSE, ARRAY[]::TEXT[];
	  RETURN;
    END IF;
  END LOOP;

   RETURN QUERY SELECT TRUE, v_partes;
  
  
END;
$$ LANGUAGE plpgsql;


-- SELECT * from verify_ip_entries('  255.168.1.1   ');                -- TRUE
-- SELECT * from verify_ip_entries('192.168.1.1:8080');                   -- TRUE
-- SELECT * from verify_ip_entries('10.0.0.1,192.168.1.1');               -- TRUE
-- SELECT * from verify_ip_entries('10.0.0.1:443,192.168.1.1:80');        -- TRUE
-- SELECT * from verify_ip_entries('10.0.0.1,192.168.1.1:80');            -- TRUE
-- SELECT * from verify_ip_entries('textual');                           -- FALSE



-- ##########################################################################################################################################################


-- DROP FUNCTION IF EXISTS public.clean_string(text)
CREATE OR REPLACE FUNCTION public.clean_string(
	entrada text)
    RETURNS text
    LANGUAGE 'plpgsql'
AS $BODY$
BEGIN
    -- Eliminar espacios, saltos de línea y tabulaciones
    RETURN regexp_replace(entrada, '[\s\n\t]+', '', 'g');
END;
$BODY$;




-- ##########################################################################################################################################################



CREATE OR REPLACE FUNCTION file_exists(file_path TEXT)
RETURNS BOOLEAN AS $$
BEGIN
  PERFORM pg_read_file(file_path, 0, 1);
  RETURN TRUE;
EXCEPTION
  WHEN OTHERS THEN
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql;


-- SELECT file_exists('/tmp/archivo.txt');       -- TRUE si el archivo existe
-- SELECT file_exists('/ruta/invalida.txt');     -- FALSE si no existe o no se puede leer
-- 
-- SELECT file_exists((select setting from pg_settings where name = 'ssl_cert_file'));  

-- ##########################################################################################################################################################

-- DROP FUNCTION parse_x509_info(p_cert TEXT);
CREATE OR REPLACE FUNCTION parse_x509_info(p_cert TEXT)
RETURNS TABLE (
  cert_type TEXT,
  issuer TEXT,
  subject TEXT,
  key_usage TEXT,
  extended_key_usage TEXT,
  alternative_name TEXT,
  basic_constraints TEXT,
  date_before TIMESTAMP,
  date_after TIMESTAMP
) AS $$
DECLARE
  matches TEXT[];
BEGIN
  -- Extraer issuer (solo primera línea)
  matches := regexp_match(p_cert, 'Issuer:\s*(.+)');
  IF matches IS NOT NULL THEN
    issuer := split_part(matches[1], E'\n', 1);
  END IF;

  -- Extraer subject (solo primera línea)
  matches := regexp_match(p_cert, 'Subject:\s*(.+)');
  IF matches IS NOT NULL THEN
    subject := split_part(matches[1], E'\n', 1);
  END IF;

  -- Key Usage (bloque de texto)
  matches := regexp_match(p_cert, 'X509v3 Key Usage: critical[\s\n]+([A-Za-z, ]+)');
  IF matches IS NOT NULL THEN
    key_usage := trim(matches[1]);
  END IF;
  
    -- Extended Key Usage (bloque de texto)
  matches := regexp_match(p_cert, 'X509v3 Extended Key Usage:[\s\n]+([A-Za-z, ]+)');
  IF matches IS NOT NULL THEN
    extended_key_usage := trim(matches[1]);
  END IF;

  -- Subject Alternative Name
  matches := regexp_match(p_cert, 'Subject Alternative Name:\s*DNS:([^\s,\n]+)');
  IF matches IS NOT NULL THEN
    alternative_name := matches[1];
  END IF;
  
    -- Subject Alternative Name
  matches := regexp_match(p_cert, 'X509v3 Basic Constraints: critical[\s\n]+([A-Za-z,:0-9. ]+)');
  IF matches IS NOT NULL THEN
    basic_constraints := trim(matches[1]);
  END IF;


 CASE
	WHEN trim(matches[1]) ~ 'CA:TRUE' AND trim(matches[1]) ~ 'pathlen:0' THEN   cert_type := 'IntermediateCA-Level0';
	WHEN trim(matches[1]) ~ 'CA:TRUE' AND trim(matches[1]) ~ 'pathlen:[1-9]' THEN cert_type := 'IntermediateCA-LevelN';
	WHEN trim(matches[1]) ~ 'CA:TRUE' AND trim(matches[1]) !~ 'pathlen' THEN cert_type := 'RootCA';
	WHEN trim(matches[1]) ~ 'CA:FALSE' THEN cert_type := 'EndEntityCertificate';
	ELSE cert_type := 'UnknownType';
END CASE;

  -- Fecha Not Before
  matches := regexp_match(p_cert, 'Not Before:\s*([A-Z][a-z]{2}.*?GMT)');
  IF matches IS NOT NULL THEN
    date_before := to_timestamp(matches[1], 'Mon DD HH24:MI:SS YYYY GMT');
  END IF;

  -- Fecha Not After
  matches := regexp_match(p_cert, 'Not After ?:?\s*([A-Z][a-z]{2}.*?GMT)');
  IF matches IS NOT NULL THEN
    date_after := to_timestamp(matches[1], 'Mon DD HH24:MI:SS YYYY GMT');
  END IF;

  RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

 
                  
 
