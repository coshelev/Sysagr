﻿
&НаКлиенте
Процедура СписокВыбор(Элемент, ВыбраннаяСтрока, Поле, СтандартнаяОбработка)
	
	Если Не ЗначениеЗаполнено(ЭтаФорма.Элементы.Список.ТекущиеДанные.СледующийВопросИлиТелНомер) Тогда
		Возврат
	КонецЕсли;
		
	//<Выбери следующее действие: переход к следующему вопросу, перевод с уведомлением, перевод без уведомления/>
	ТекДанные = ЭтаФорма.Элементы.Список.ТекущиеДанные.СледующийВопросИлиТелНомер;
	ТипЗначенияОтвета=ТипЗнч(ТекДанные);
	Если  ТипЗначенияОтвета = Тип("СправочникСсылка.Анкеты") Тогда
		
		ТаблицаНавигацииНазад_ДобавитьЗапись(ЭтаФорма.Элементы.Список.ТекущиеДанные.СледующийВопросИлиТелНомер, ЭтаФорма.Вопрос);
		ПокажиСледующийВопрос(ЭтаФорма.Элементы.Список.ТекущиеДанные.СледующийВопросИлиТелНомер)
		
	ИначеЕсли ТипЗначенияОтвета = Тип("СправочникСсылка.ТелВнутренние") 
		И ЗначениеЗаполнено(ЭтаФорма.Параметры.КаналСистемный) 
		Тогда
		
		Результат = КонтактЦентр.КомандаAtxfer(ЭтаФорма.Параметры.КаналСистемный,ТекДанные);
		ТекстСообщения = ?(Результат,"Перевод выполнен","Ошибка перевода звонка");
		ПоказатьПредупреждение(,ТекстСообщения,3);
		
		ЭтаФорма.Закрыть();
		
	ИначеЕсли ТипЗначенияОтвета = Тип("СправочникСсылка.ТелОчереди")
		И ЗначениеЗаполнено(ЭтаФорма.Параметры.КаналСистемный)  
		Тогда
		
		Результат = КонтактЦентр.КомандаBlindTransfer(ЭтаФорма.Параметры.КаналСистемный,ТекДанные);
		ТекстСообщения = ?(Результат,"Перевод выполнен","Ошибка перевода звонка");
		ПоказатьПредупреждение(,ТекстСообщения,3);

		ЭтаФорма.Закрыть();
	КонецЕсли;
	//</Выбери следующее действие: переход к следующему вопросу, перевод с уведомлением, перевод без уведомления>

КонецПроцедуры

&НаКлиенте
Процедура ПокажиСледующийВопрос(СледующийВопросИлиТелНомер)
	
	//<Настройка и установка отбора/>
	ЭтаФорма.Список.КомпоновщикНастроек.ПользовательскиеНастройки.Элементы[0].Элементы.Очистить();

	//<Отбор по группе>
	ЭтаФорма.Список.КомпоновщикНастроек.ПользовательскиеНастройки.Элементы[0].Элементы.Очистить();
	ЭлОтбора1 = ЭтаФорма.Список.КомпоновщикНастроек.ПользовательскиеНастройки.Элементы[0].Элементы.Добавить(Тип("ЭлементОтбораКомпоновкиДанных"));
	ЭлОтбора1.ЛевоеЗначение=Новый ПолеКомпоновкиДанных("НаименованиеГруппы");
	ЭлОтбора1.ПравоеЗначение="КОНСОЛЬ_ИСХОДЯЩИХ";
	ЭлОтбора1.ВидСравнения=ВидСравненияКомпоновкиДанных.Содержит;
	ЭлОтбора1.Использование=Истина;	
	//</Отбор по группе>

	//<Отбор по следующему вопросу (содержится в ответе отображаемого вопроса>
	ЭтаФорма.Список.КомпоновщикНастроек.ПользовательскиеНастройки.Элементы[0].Элементы.Очистить();
	ЭлОтбора1 = ЭтаФорма.Список.КомпоновщикНастроек.ПользовательскиеНастройки.Элементы[0].Элементы.Добавить(Тип("ЭлементОтбораКомпоновкиДанных"));
	ЭлОтбора1.ЛевоеЗначение=Новый ПолеКомпоновкиДанных("Ссылка");
	ЭлОтбора1.ПравоеЗначение=СледующийВопросИлиТелНомер;
	ЭлОтбора1.ВидСравнения=ВидСравненияКомпоновкиДанных.Равно;
	ЭлОтбора1.Использование=Истина;	
	//</Отбор по следующему вопросу (содержится в ответе отображаемого вопроса>

	//<Отображение нового вопроса в шапке/>
	ЭтаФорма.Вопрос=ЭлОтбора1.ПравоеЗначение;
	ЭтаФорма.ВопросСтрокой = ЭлОтбора1.ПравоеЗначение;
	
КонецПроцедуры

&НаСервере
Процедура ПриСозданииНаСервере(Отказ, СтандартнаяОбработка)
	
		
	Если ЗначениеЗаполнено(ЭтаФорма.Параметры.Телефон) Тогда
		
		РегСсылка = Конвертация.РегионПолучитьПоНомеруТелефона(ЭтаФорма.Параметры.Телефон);
		Если РегСсылка <> Справочники.Страны.ПустаяСсылка() Тогда
			Запрос = Новый Запрос();
			Запрос.Текст = 
			"ВЫБРАТЬ Т.Ссылка КАК Ссылка, Т.СледующийВопросИлиТелНомер КАК СледующийВопросИлиТелНомер
			|ИЗ Справочник.Анкеты.ВариантыОтветов КАК Т
			|ГДЕ
			|	Т.Ссылка.ЭтоГруппа = ЛОЖЬ
			|	И Т.Ссылка.Родитель.Наименование ПОДОБНО &НаименованиеГруппы
			|	И Т.Ответ ПОДОБНО &Ответ";
			
			Запрос.УстановитьПараметр("НаименованиеГруппы", "%КОНСОЛЬ_ИСХОДЯЩИХ%");	
			НаименованиеРегиона = РегСсылка.Наименование;
			Запрос.УстановитьПараметр("Ответ", "%"+НаименованиеРегиона+"%");
			
			РезультатЗапроса = Запрос.Выполнить();
			Если Не РезультатЗапроса.Пустой() Тогда
				Выборка = РезультатЗапроса.Выбрать();
				Выборка.Следующий();
				ПервыйВопрос = Выборка.СледующийВопросИлиТелНомер;
				ТаблицаНавигацииНазад_ДобавитьЗапись_НаСервере(Выборка.СледующийВопросИлиТелНомер, Выборка.Ссылка);	
			КонецЕсли;
		КонецЕсли;
	КонецЕсли;

	Если Не ЗначениеЗаполнено(ПервыйВопрос) Тогда
	
		Запрос = Новый Запрос("ВЫБРАТЬ Ссылка ИЗ Справочник.Анкеты ГДЕ Порядок = 1 И ЭтоГруппа = ЛОЖЬ И Родитель.Наименование ПОДОБНО &НаименованиеГруппы");
		Запрос.УстановитьПараметр("НаименованиеГруппы", "%КОНСОЛЬ_ИСХОДЯЩИХ%");
		РезультатЗапроса = Запрос.Выполнить();
		Если РезультатЗапроса.Пустой() Тогда
			Возврат;
		КонецЕсли;
	
		ПервыйВопрос = РезультатЗапроса.Выгрузить()[0][0];
	КонецЕсли;

	ЭтаФорма.Список.КомпоновщикНастроек.ПользовательскиеНастройки.Элементы[0].Элементы.Очистить();
	ЭлОтбора1 = ЭтаФорма.Список.КомпоновщикНастроек.ПользовательскиеНастройки.Элементы[0].Элементы.Добавить(Тип("ЭлементОтбораКомпоновкиДанных"));
	ЭлОтбора1.ЛевоеЗначение=Новый ПолеКомпоновкиДанных("Ссылка");
	ЭлОтбора1.ПравоеЗначение=ПервыйВопрос;
	ЭлОтбора1.ВидСравнения=ВидСравненияКомпоновкиДанных.Равно;
	ЭлОтбора1.Использование=Истина;	
	
	ЭтаФорма.Вопрос = ПервыйВопрос;
	ЭтаФорма.ВопросСтрокой = ПервыйВопрос;
		
КонецПроцедуры


//<Обработка гиперссылки Назад в маршрутных вопросах>
&НаСервере
Процедура ТаблицаНавигацииНазад_ДобавитьЗапись_НаСервере(ТекущийВопрос, ПредыдущийВопрос)
	Если ТипЗнч(ТекущийВопрос)<>Тип("СправочникСсылка.Анкеты") Тогда
		Возврат
	КонецЕсли;
	ПарамОтбора = Новый Структура("ТекущийВопрос", ТекущийВопрос);
	НайденныеСтроки = ЭтаФорма.ТаблицаНавигацииНазад.НайтиСтроки(ПарамОтбора);
	Если НайденныеСтроки.Количество()=1 Тогда
		НоваяСтрока = НайденныеСтроки[0];
	ИначеЕсли НайденныеСтроки.Количество()= 0 Тогда
		НоваяСтрока = ЭтаФорма.ТаблицаНавигацииНазад.Добавить();
	Иначе
		Возврат
	КонецЕсли;
	НоваяСтрока.ТекущийВопрос = ТекущийВопрос;
	НоваяСтрока.ПредыдущийВопрос = ПредыдущийВопрос 
КонецПроцедуры

&НаКлиенте
Процедура ТаблицаНавигацииНазад_ДобавитьЗапись(ТекущийВопрос, ПредыдущийВопрос)
	Если ТипЗнч(ТекущийВопрос)<>Тип("СправочникСсылка.Анкеты") Тогда
		Возврат
	КонецЕсли;
	ПарамОтбора = Новый Структура("ТекущийВопрос", ТекущийВопрос);
	НайденныеСтроки = ЭтаФорма.ТаблицаНавигацииНазад.НайтиСтроки(ПарамОтбора);
	Если НайденныеСтроки.Количество()=1 Тогда
		НоваяСтрока = НайденныеСтроки[0];
	ИначеЕсли НайденныеСтроки.Количество()= 0 Тогда
		НоваяСтрока = ЭтаФорма.ТаблицаНавигацииНазад.Добавить();
	Иначе
		Возврат
	КонецЕсли;
	НоваяСтрока.ТекущийВопрос = ТекущийВопрос;
	НоваяСтрока.ПредыдущийВопрос = ПредыдущийВопрос 
КонецПроцедуры

&НаКлиенте
Процедура ТаблицаНавигацииНазад_УдалитьЗапись(ТекущийВопрос)
	ПарамОтбора = Новый Структура("ТекущийВопрос", ТекущийВопрос);
	НайденныеСтроки = ЭтаФорма.ТаблицаНавигацииНазад.НайтиСтроки(ПарамОтбора);
	Если НайденныеСтроки.Количество()=1 Тогда
		ЭтаФорма.ТаблицаНавигацииНазад.Удалить(НайденныеСтроки[0]);
	КонецЕсли;
КонецПроцедуры
	
&НаКлиенте
Функция ТаблицаНавигацииНазад_НайдиПредыдущийВопрос(ТекущийВопрос)
	ПарамОтбора = Новый Структура("ТекущийВопрос", ТекущийВопрос);
	НайденныеСтроки = ЭтаФорма.ТаблицаНавигацииНазад.НайтиСтроки(ПарамОтбора);
	Если НайденныеСтроки.Количество()=1 Тогда
		Возврат НайденныеСтроки[0].ПредыдущийВопрос;
	Иначе
		Возврат неопределено;
	КонецЕсли;
КонецФункции

&НаКлиенте
Процедура Назад(Команда)
	ПредВопрос = ТаблицаНавигацииНазад_НайдиПредыдущийВопрос(ЭтаФорма.Вопрос);
	Если ПредВопрос<>Неопределено Тогда
		ТаблицаНавигацииНазад_УдалитьЗапись(ЭтаФорма.Вопрос);
		ПокажиСледующийВопрос(ПредВопрос);
	КонецЕсли;	
КонецПроцедуры

//</Обработка гиперссылки Назад в маршрутных вопросах>



