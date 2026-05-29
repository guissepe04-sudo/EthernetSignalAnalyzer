
from collections import defaultdict 
import numpy as np 
from .parser import parse_raw_packet ,parse_tcp16_stream ,_PROTO_TCP16 


def analyze_signals (packets :list ,transport_filter :str ,
src_filter :str ,dst_filter :str )->dict :
    """
    Procesa paquetes y devuelve dict:
      (signal_id, transport, ip_src, ip_dst) -> info_dict

    info_dict contiene: signal_id (int), ts, val, is_float, cat,
                        min, max, std, range, n, transport, ip_src, ip_dst
    """
    sig_ts =defaultdict (list )
    sig_val =defaultdict (list )
    sig_payload =defaultdict (list )
    sig_float_n =defaultdict (int )
    sig_int_n =defaultdict (int )
    sig_cat ={}

    def _accept (pkt ):
        if transport_filter not in ("Todos","")and pkt ["transport"]!=transport_filter :
            return False 
        if src_filter and pkt ["ip_src"]!=src_filter :
            return False 
        if dst_filter and pkt ["ip_dst"]!=dst_filter :
            return False 
        return True 

    filtered =[p for p in packets if _accept (p )]


    for pkt in filtered :
        if pkt ["transport"]!="UDP":
            continue 
        ver ,entries =parse_raw_packet (pkt ["payload"])
        if ver not in (1 ,2 ):
            continue 
        for sig_id ,val ,is_f ,cat ,raw in entries :
            key =(sig_id ,"UDP",pkt ["ip_src"],pkt ["ip_dst"])
            sig_ts [key ].append (pkt ["ts"])
            sig_val [key ].append (val )
            sig_payload [key ].append (raw )
            if is_f :
                sig_float_n [key ]+=1 
            else :
                sig_int_n [key ]+=1 
            sig_cat [key ]=cat 




    tcp_streams =defaultdict (list )
    for pkt in filtered :
        if pkt ["transport"]=="TCP":
            tcp_streams [(pkt ["ip_src"],pkt ["ip_dst"])].append (pkt )

    for (ip_src ,ip_dst ),stream_pkts in tcp_streams .items ():
        stream_pkts .sort (key =lambda p :p ["ts"])
        buf =b''
        for pkt in stream_pkts :
            try :
                chunk =bytes .fromhex (
                pkt ["payload"].replace (" ","").replace (":",""))
            except ValueError :
                continue 
            buf +=chunk 
            entries ,buf =parse_tcp16_stream (buf )
            for sig_id ,val ,is_f ,cat ,raw in entries :
                key =(sig_id ,"TCP",ip_src ,ip_dst )
                sig_ts [key ].append (pkt ["ts"])
                sig_val [key ].append (val )
                sig_payload [key ].append (raw )
                if is_f :
                    sig_float_n [key ]+=1 
                else :
                    sig_int_n [key ]+=1 
                sig_cat [key ]=cat 


    result ={}
    for key in sig_ts :
        vals =sig_val [key ]
        if not vals :
            continue 
        arr =np .array (vals ,dtype =float )

        if arr .max ()==0 and arr .min ()==0 :
            continue 
        sig_id ,transport ,ip_src ,ip_dst =key 
        is_float =sig_float_n [key ]>=sig_int_n [key ]
        result [key ]={
        "signal_id":sig_id ,
        "ts":sig_ts [key ],
        "val":vals ,
        "payloads":sig_payload [key ],
        "is_float":is_float ,
        "cat":sig_cat .get (key ,0 ),
        "min":float (arr .min ()),
        "max":float (arr .max ()),
        "std":float (arr .std ()),
        "range":float (arr .max ()-arr .min ()),
        "n":len (vals ),
        "transport":transport ,
        "ip_src":ip_src ,
        "ip_dst":ip_dst ,
        }
    return result 


def find_duplicate_groups (signals :dict )->dict :
    """
    Detecta señales con series temporales idénticas (mismo timestamp, mismo valor).
    Retorna dict: sig_key -> [lista de claves de señales gemelas].
    Solo compara señales dentro del mismo bucket estadístico para ser eficiente.
    """
    buckets =defaultdict (list )
    for k ,v in signals .items ():
        bkey =(round (v ['min'],2 ),round (v ['max'],2 ),v ['n'],round (v ['std'],2 ))
        buckets [bkey ].append (k )

    result ={}
    for candidates in buckets .values ():
        if len (candidates )<2 :
            continue 
        vals_cache ={k :np .array (signals [k ]['val'])for k in candidates }
        ts_cache ={k :np .array (signals [k ]['ts'])for k in candidates }
        for i in range (len (candidates )):
            for j in range (i +1 ,len (candidates )):
                k1 ,k2 =candidates [i ],candidates [j ]
                if signals [k1 ]['n']!=signals [k2 ]['n']:
                    continue 
                if not np .allclose (ts_cache [k1 ],ts_cache [k2 ],atol =0.05 ):
                    continue 
                if np .allclose (vals_cache [k1 ],vals_cache [k2 ],rtol =1e-4 ,atol =0 ):
                    result .setdefault (k1 ,[]).append (k2 )
                    result .setdefault (k2 ,[]).append (k1 )
    return result 


def expand_signal_types (signals :dict )->dict :
    """
    Para cada señal en el dict, genera entradas adicionales con todas las
    interpretaciones de tipo válidas (float32 LE/BE, uint32, int32, float64...).

    Las entradas originales conservan su clave de 4 elementos.
    Las variantes usan una clave de 5 elementos:
      (signal_id, transport, ip_src, ip_dst, decode_tag)
    donde decode_tag es p.ej. "float32 LE", "uint32 BE", "float64 LE", etc.

    Solo agrega variantes que produzcan valores distintos a la serie original.
    """
    from .parser import get_all_valid_configs ,decode_with_override 

    expanded =dict (signals )

    for base_key ,info in signals .items ():
        payloads =info .get ("payloads",[])
        transport =info .get ("transport","UDP")
        if not payloads :
            continue 

        configs =get_all_valid_configs (payloads [0 ],transport )

        for label ,vsize ,dtype ,endian ,extra in configs :
            variant_key =base_key +(label ,)

            new_vals ,new_ts =[],[]
            for i ,raw in enumerate (payloads ):
                v ,_ =decode_with_override (raw ,transport ,vsize ,dtype ,endian ,extra )
                if v is not None :
                    new_vals .append (float (v ))
                    new_ts .append (info ["ts"][i ]if i <len (info ["ts"])else 0.0 )

            if not new_vals :
                continue 

            arr =np .array (new_vals ,dtype =float )


            if not np .all (np .isfinite (arr )):
                arr =arr [np .isfinite (arr )]
                new_ts =[new_ts [i ]for i ,v in enumerate (new_vals )if np .isfinite (v )]
                new_vals =[v for v in new_vals if np .isfinite (v )]
                if len (new_vals )<2 :
                    continue 

            if arr .max ()==0 and arr .min ()==0 :
                continue 

            mn =float (arr .min ())
            mx =float (arr .max ())
            rng =mx -mn 
            std =float (arr .std ())if np .isfinite (arr .std ())else 0.0 

            expanded [variant_key ]={
            "signal_id":info ["signal_id"],
            "ts":new_ts ,
            "val":new_vals ,
            "payloads":payloads ,
            "is_float":dtype =="float",
            "cat":info .get ("cat",0 ),
            "min":mn ,
            "max":mx ,
            "std":std ,
            "range":rng if np .isfinite (rng )else 0.0 ,
            "n":len (new_vals ),
            "transport":transport ,
            "ip_src":info ["ip_src"],
            "ip_dst":info ["ip_dst"],
            "decode_tag":label ,
            }

    return expanded 


def sig_type (info :dict )->str :
    return "float"if info ["is_float"]else "int"


def is_digital (info :dict )->bool :
    return not info ["is_float"]and info ["max"]<=10 
