global t1: table[addr] of string;
global t2: table[addr] of string;
global t3: table[addr] of string;

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	if(name == "USER-AGENT")
	{
		if ( c$id$orig_h !in t1 )
		{
			t1[c$id$orig_h]=value;
		}
		else
		{
			if( t1[c$id$orig_h] != value )
			{
				if(c$id$orig_h !in t2)
				{
					t2[c$id$orig_h]=value;
				}
				else
				{
					if( t2[c$id$orig_h] != value)
					{
						if(c$id$orig_h !in t3)
						{
						t3[c$id$orig_h]="OK";
						print fmt("%s is a proxy",c$id$orig_h);
						}
					}
				}
			}
		}
	}
}


event zeek_done()
	{
	}