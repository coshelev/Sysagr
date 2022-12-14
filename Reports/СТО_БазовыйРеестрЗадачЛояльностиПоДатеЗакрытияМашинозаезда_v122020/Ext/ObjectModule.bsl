Процедура ПриКомпоновкеРезультата(ДокументРезультат, ДанныеРасшифровки, СтандартнаяОбработка)
	ПараметрыДанных = КомпоновщикНастроек.Настройки.ПараметрыДанных;
	ПараметрыДанных.УстановитьЗначениеПараметра("Начало", 												Период.ДатаНачала);
	ПараметрыДанных.УстановитьЗначениеПараметра("Окончание", 											Период.ДатаОкончания);
	ПараметрыДанных.УстановитьЗначениеПараметра("ДовольныЛиВыПоследнимПосещениемСтанции",				Анкета._1йБазовыйВопросЛояльности());	
	ПараметрыДанных.УстановитьЗначениеПараметра("ДостоинЛиНашСервисВашейРекомендацииДрузьямИЗнакомым",	Анкета._2йБазовыйВопросЛояльности());
	ПараметрыДанных.УстановитьЗначениеПараметра("_1",													Анкета._1());
	ПараметрыДанных.УстановитьЗначениеПараметра("_2",													Анкета._2());
	ПараметрыДанных.УстановитьЗначениеПараметра("_3",													Анкета._3());
	ПараметрыДанных.УстановитьЗначениеПараметра("Нет",													Анкета.Нет());
	Для Каждого Парам Из ПараметрыДанных.Элементы Цикл
		Если Не ЗначениеЗаполнено(Парам.Значение) Тогда
			Сообщить("Не заполнен параметр: "+Парам.Параметр);
		КонецЕсли;
	КонецЦикла;
КонецПроцедуры

