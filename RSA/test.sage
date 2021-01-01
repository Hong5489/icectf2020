n = 460587847615321545312743112252681790529241995267520194089525006811445797148215192958348208384100142625634776957101208367836344890493123396256822067252454897370390919427503445239821745976720507227436990557330541596289387435466788792568238908859871724153573363204461793078176839890623142327864107813628367354874370992657805921933861244082061933530624507832723985891622538797271515813663783580973125731383848760835580786736541766700201586419207200285649518054917604740159198073136117252885773374341783995548367471015835659055652140098740368186458564858880400360536245384799742760597577398131816896767617208800067231267634260432369105083958817471773145223005496759178303810037977227302021311566238756530119560743589928314868307009151319439817700221656798613828676769720182396527775389082127492220218210430483482534338782234871817901827374509408391601928268025696596334315917182661132476182242062862853496614774368349052951570507517030347774920427858561905933873552683958779359325094033354038916131060953624074072701970886823355848591266722504297843135442416876771590941977753051363618953113917155470509518964566312402729432375615274667408329565775798030471833886758672712528273187134051868777945407133565900890344488190073927347338584043807286967483962717966300396984192006533050265348776012875883708142654253868881880293195035097400420731344709157126633944371617967838646865444062352505785976552588932487750409110356025456989907329167858117742506021543356248698832132093799060550535747511124214583855242178714068505268805853154285730197095600008875781778348239964757563706524480110749009504461618656084904290305714510768172794453041351549727381782324079507011253542957794139224454431183054919612635090277084110566333797818032500143500532664219223575407027410789904844927462552314613956629743945514940757624468030604824079333982444442232295379767067076479593469582786989277735008136591353003384103665517989311751745638856100259922754872554807838160211742877953752024379954317863868261030702391668774247610925379512304045779772579935259802865661249683745877462405996365079014672674809518943937107377437054507437070637886968491708430879767581698357853968421528718990831152377773930434191868718560551698466012662942808051147126074571400597367977230302822648531622843213589318319190634935548955305512082525228217247213333535482772800587883921544114433390032314156171967446698851513627000087137183607759805779294472721875365376553208433419389395131576043257675739482307818063
p = PolynomialRing(RationalField(), 'p').gen()
for c in range(10000):
	e = p^2 + (2^4096+c)*p - n
	if e.roots():
		print e.roots()
		print c