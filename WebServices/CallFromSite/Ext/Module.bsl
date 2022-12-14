Функция DataGet(PhoneNum, Site, Extra = "")
	//Выполняет автозвонок
	
	ЗначениеПоУмолчанию = "";
	
	Доступно = ЗначениеЗаполнено(PhoneNum);
	
	Если Не Доступно Тогда
		Возврат "error 01";
	КонецЕсли;
	
	Если PhoneNum = "9506080025" Тогда
		Возврат "<div><div><p>test</p></div></div>";
	КонецЕсли;
	
	//Сформируй ИД интернет-заявки
	//----------------------------------
	Ид = Новый УникальныйИдентификатор();
	Сигнатура = xmlСтрока(Ид);
	
	ТекДата = ТекущаяДата();
	
	//Добавь интернет-заявку
	//--------------------------------------------------------------------------------------------
	Выполнено = РегистрыСведений.ИнтернетЗаявки.Добавить(Сигнатура, ТекДата, Site, PhoneNum, Extra);
	Если Не Выполнено Тогда
		Возврат "error 011"
	КонецЕсли;
	
	// Заполни свойства интернет-заявки
	//---------------------------------------------------------------------------------
	Результат = "";
	Если Лев(Extra, 1)="{" Тогда
		Результат = РегистрыСведений.ИнтернетЗаявкиСвойства.Добавить(Сигнатура, Extra);
	КонецЕсли; 
	
	//По интернет-заявкам со свойством "form type" = "Заказать выездную презентацию" не создаем задач,
	//отправляем письмо менеджеру
	Если Результат = "Выполнено. Заказать выездную презентацию" Тогда
		Если ЗадачиСервер.ЭтоИнтенетЗаявкаФормы_ЗаказатьВыезднуюПрезентацию(Сигнатура) Тогда
			Возврат "error 012";
		КонецЕсли;	
	КонецЕсли;
	
	//Сконвертируй номер телефона
	//---------------------------------------------------------
	Телефон = Конвертация.ТелефонВнешнийНормализовать(PhoneNum);
	
	//Если после конвертации в номере остались не цифры - задачу не создаем
	//---------------------------------------------------------------------
	Если Не Конвертация.ЭтоТолькоЦифры(Телефон) Тогда
		Возврат ЗначениеПоУмолчанию;
	КонецЕсли;
	
	//Добавить префикс выхода на международную линию, если телефонный номер зарубежный
	//--------------------------------------------------------------------------------
	Если СтрДлина(Телефон)>=10 Тогда
		Запрос = Новый Запрос();
		Запрос.Текст = 
		"ВЫБРАТЬ ПЕРВЫЕ 1
		|	ТелНомерныеПланы.Страна КАК Страна
		|ИЗ
		|	РегистрСведений.ТелНомерныеПланы КАК ТелНомерныеПланы
		|ГДЕ
		|	ТелНомерныеПланы.НачДиапазона >= &Телефон
		|	И ТелНомерныеПланы.КонДиапазона <= &Телефон
		|	И ТелНомерныеПланы.Страна.Наименование <> &Наименование";
		Запрос.УстановитьПараметр("Телефон", Число(Телефон));
		Запрос.УстановитьПараметр("Наименование", "Российская Федерация");
		РезультатЗапроса = ОбщегоНазначения.ВыполнитьЗапрос(Запрос);
		Если Не РезультатЗапроса.Пустой() Тогда
			Телефон = "810"+Телефон;
		КонецЕсли;
	КонецЕсли;
	
	ЗакройЗадачу = Ложь;
	
	//Если свойство form_type = "Регистрация" или  form_type = "Диалог в чает" нужно и создать задачу и сразу ее закрыть
	//----------------------------------------------------------------------------------------------------------------
	Если Результат = "Выполнено. Регистрация" Тогда
		ЗакройЗадачу = Истина;
	КонецЕсли;
	
	ЗадачиСервер.СоздайЗадачуКакЗаявкуИлиКакАвтозвонок(Телефон, Site, Сигнатура, ЗакройЗадачу);
	
	Возврат "accepted"
КонецФункции

Функция LeadGenic(prop)
	// Вставить содержимое обработчика.
КонецФункции
