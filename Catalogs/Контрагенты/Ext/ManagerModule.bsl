Функция  ПолучиТаблицуИдентификаторовПоРеквизиту(ТипДанных, ИмяРеквизита="Код", ЗначениеРеквизита) экспорт
	// Заполняет основное поле строки поля ГУИД, а также вспомогательный поля Период, ИсточникДанных, ТипДанныхXML, перезаполняет поле Представление
	
	Результат = Новый ТаблицаЗначений();
	ЗначениеПоУмолчанию = Результат;
		
	Доступно = 	ТипЗнч(ТипДанных) = Тип("СправочникСсылка.ИБ_ТипыДанных")
				И ЗначениеЗаполнено(ТипДанных)
				И ЗначениеЗаполнено(ТипДанных.ИсточникДанных.ПараметрыСоединения)
				И ТипЗнч(ИмяРеквизита) = Тип("Строка")
				И ЗначениеЗаполнено(ИмяРеквизита)
				И ТипЗнч(ЗначениеРеквизита) = Тип("Строка")
				И ЗначениеЗаполнено(ЗначениеРеквизита);
	Если Не Доступно Тогда
		ЗаписьЖурналаРегистрации("ЗаполниитьИсточникДанныхПоРеквизиту", УровеньЖурналаРегистрации.Ошибка, "ТипДанных = "+ТипДанных+"; ИмяРеквизита = "+ИмяРеквизита+"; ЗначениеРеквизита = "+ЗначениеРеквизита, "Ошибка в типе или заполнении аргументов");
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;
	
	БИ = ОбщегоНазначения.ПолучитьПодключениеБД(ТипДанных.ИсточникДанных.ПараметрыСоединения);
	БИ_Запрос =  БИ.NewObject("Запрос");
	ТекстЗапроса =  "ВЫБРАТЬ	ПРЕДСТАВЛЕНИЕ(УНИКАЛЬНЫЙИДЕНТИФИКАТОР(Т.Ссылка)) КАК Ссылка, Т.Код КАК Код, Т.Наименование КАК Наименование
	                |ИЗ			Справочник.Контрагенты КАК Т
	                |ГДЕ		Т.Код = &ЗначениеРеквизита";
	ТекстЗапроса = ?(ВРЕГ(СокрЛП(ИмяРеквизита))<> "КОД",  СтрЗаменить(ТекстЗапроса, "Код", СокрЛП(ИмяРеквизита)), ТекстЗапроса);   
	БИ_Запрос.Текст = ТекстЗапроса;
	БИ_Запрос.УстановитьПараметр("ЗначениеРеквизита", ЗначениеРеквизита);	
	Попытка
		БИ_РезультатЗапроса = БИ_Запрос.Выполнить();
	Исключение
		ЗаписьЖурналаРегистрации("ЗаполниитьИсточникДанныхПоРеквизиту", УровеньЖурналаРегистрации.Ошибка, "ТекстЗапроса="+ТекстЗапроса, "Ошибка выполнения запроса в базе-источнике:"+ПодробноеПредставлениеОшибки(ИнформацияОбОшибке()));
	КонецПопытки;
	
	ОписТипаСтрока = Новый ОписаниеТипов("Строка");
	
	Результат.Колонки.Добавить("Идентификатор", 	ОписТипаСтрока);
	Результат.Колонки.Добавить("Код", 				ОписТипаСтрока);
	Результат.Колонки.Добавить("Наименование",	 	ОписТипаСтрока);
	Результат.Колонки.Добавить("ТипДанныхXML",	 	ОписТипаСтрока);
		
	БИ_Выборка = БИ_РезультатЗапроса.Выбрать();
	Пока БИ_Выборка.Следующий() Цикл
		НоваяСтрока = Результат.Добавить();
		
		ТипДанныхXML = БИ.СериализаторXDTO.XMLТипЗнч(БИ_Выборка.Ссылка);	
		Если ТипДанныхXML <> Неопределено Тогда
			НоваяСтрока.ТипДанныхXML	= ТипДанныхXML.URIПространстваИмен+":"+ТипДанныхXML.ИмяТипа;
		КонецЕсли;

		НоваяСтрока.Идентификатор	=	БИ_Выборка.Ссылка;
		НоваяСтрока.Код				=	БИ_Выборка.Код;
		НоваяСтрока.Наименование	=	БИ_Выборка.Наименование;
	КонецЦикла;
	
	Возврат Результат
КонецФункции

Функция НайдиПоКонтактнымДанным(КонтактныеДанные) Экспорт
	//Возвращает ссылку на контрагента по параметру КонтактныеДанные - номер телефона, адред эл.почты и прочие
	
	Доступно = ТипЗнч(КонтактныеДанные) = Тип("Строка") И СтрДлина(КонтактныеДанные)>4;	
	Если Не Доступно Тогда
		Возврат Справочники.Контрагенты.ПустаяСсылка();
	КонецЕсли;
	
	Запрос = Новый Запрос("ВЫБРАТЬ Первые 1 Ссылка ИЗ Справочник.Контрагенты ГДЕ КонтактнаяИнформация.Значение = &Значение");
	Запрос.УстановитьПараметр("Значение", КонтактныеДанные);
	РЗ = Запрос.Выполнить();	
	Рез = ?(РЗ.Пустой(), Справочники.Контрагенты.ПустаяСсылка(), РЗ.Выгрузить()[0][0]);
	Возврат Рез;
КонецФункции	

